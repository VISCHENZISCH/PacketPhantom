"""Session TUI complète pilotée au clavier sur un pcap de démonstration."""
import asyncio

import pytest

from packetphantom import export, pcapio
from packetphantom.engine import Engine, EngineConfig
from packetphantom.geoip import GeoResolver
from packetphantom.ui.app import PhantomApp
from packetphantom.ui.screens import FollowStreamScreen, HelpScreen

from .conftest import TS


@pytest.fixture
def pcap(tmp_path, frames):
    demo = [
        frames.dns_query("example.com"), frames.dns_answer("example.com", "93.184.216.34"),
        frames.syn(), frames.synack(), frames.tls_client_hello("example.com"),
        frames.http_get("/index.php", "10.0.0.9"), frames.basic_auth("admin", "hunter2"),
        frames.tcp(b"[/] [bold]markup injection[/bold] [link=x]", dport=7777),
        frames.arp_reply(mac="aa:aa:aa:aa:aa:aa"), frames.arp_reply(mac="66:66:66:66:66:66"), frames.ping(),
    ]
    path = tmp_path / "demo.pcap"
    pcapio.write(path, ((data, TS + i * 0.01, 1) for i, data in enumerate(demo)))
    return path


async def wait_for(pilot, condition, timeout=5.0):
    for _ in range(int(timeout / 0.1)):
        if condition():
            return
        await pilot.pause(0.1)
    raise AssertionError("condition non atteinte")


def test_full_ui_session(pcap, tmp_path, monkeypatch):
    monkeypatch.setattr(export, "EXPORT_DIR", tmp_path / "exports")

    async def scenario():
        engine = Engine(EngineConfig(buffer=1000))
        app = PhantomApp(engine, GeoResolver("off"), read=str(pcap), autostart=False)
        async with app.run_test(size=(160, 48)) as pilot:
            packets = app.query_one("#packets")
            await wait_for(pilot, lambda: packets.row_count == 11)
            assert engine.stats.alerts[4] >= 1   # identifiants HTTP Basic

            # Détail de chaque paquet (y compris celui qui contient du markup Rich)
            for row in range(packets.row_count):
                packets.move_cursor(row=row)
                await pilot.pause(0.08)
            assert app.selected_pid == 11

            # Filtre d'affichage saisi au clavier
            await pilot.press("slash", *"tls", "space", *"or", "space", *"dns", "enter")
            await wait_for(pilot, lambda: packets.row_count == 3)
            assert not app.apply_filter("port ==") and packets.row_count == 3
            await pilot.press("escape")
            await wait_for(pilot, lambda: packets.row_count == 11)

            # Suivi de flux
            app.apply_filter("http", select=6)
            packets.focus()
            await pilot.press("f")
            await wait_for(pilot, lambda: isinstance(app.screen, FollowStreamScreen))
            await pilot.press("h", "d", "escape")

            # Onglets
            for key, table in (("2", "#flows"), ("3", "#hosts"), ("4", "#alerts")):
                await pilot.press(key)
                await wait_for(pilot, lambda table=table: app.query_one(table).row_count >= 2)
            await pilot.press("5")

            # Pivot depuis une alerte
            await pilot.press("4")
            app.query_one("#alerts").focus()
            await pilot.press("enter")
            await wait_for(pilot, lambda: app.query_one("#tabs").active == "tab-packets" and app._filter_text)

            # Thème, pause, aide
            await pilot.press("t")
            await pilot.pause(0.2)
            assert app.theme == "phantom-light"
            await pilot.press("p", "p", "question_mark")
            await wait_for(pilot, lambda: isinstance(app.screen, HelpScreen))
            await pilot.press("escape")

            # Exports
            for kind in ("pcap-view", "pcap-all", "csv-view", "flows", "hosts", "alerts"):
                path = app._export(kind)
                assert path.exists() and path.stat().st_size > 0, kind

            await pilot.press("c")
            await wait_for(pilot, lambda: packets.row_count == 0)
        engine.close()

    asyncio.run(scenario())

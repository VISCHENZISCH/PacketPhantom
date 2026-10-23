"""Globe : coordonnées GeoIP, position du réseau local, trajets agrégés et page web."""
import json

import pytest
import requests

from packetphantom import analytics
from packetphantom.api import Api
from packetphantom.cli import build_parser
from packetphantom.engine import Engine, EngineConfig
from packetphantom.geoip import GeoInfo, GeoResolver

from .conftest import feed

HOME = (48.85, 2.35)
US = GeoInfo("US", "États-Unis", "Norwell", "NA", 42.15, -70.82)
AU = GeoInfo("AU", "Australie", "Sydney", "OC", -33.87, 151.2)


def located(home=HOME) -> GeoResolver:
    geo = GeoResolver("off", home=home)
    geo._cache.update({"93.184.216.34": US, "1.1.1.1": AU})   # résolutions déjà faites
    return geo


@pytest.fixture
def traffic(engine, frames):
    # sortant vers US, réponse entrante, DNS sortant vers AU, ping vers une IP non localisée (ignoré)
    feed(engine, frames.syn(), frames.synack(), frames.dns_query(), frames.ping())
    return engine


def test_arcs_are_aggregated_with_direction(traffic):
    data = analytics.geo_traffic(traffic, located(), after=0)
    assert data["home"]["lat"] == HOME[0] and data["last_id"] == 4
    assert (data["packets"], data["placed"]) == (4, 3)
    arcs = {(a["from"]["country"], a["to"]["country"]): a for a in data["arcs"]}
    assert {key: arc["direction"] for key, arc in arcs.items()} == {
        ("LAN", "US"): "out", ("US", "LAN"): "in", ("LAN", "AU"): "out"}
    assert arcs[("LAN", "AU")]["proto"] == "DNS" and arcs[("LAN", "AU")]["to"]["city"] == "Sydney"

    later = analytics.geo_traffic(traffic, located(), after=data["last_id"])
    assert later["arcs"] == [] and later["last_id"] == 4


def test_without_home_local_traffic_is_not_placed(traffic):
    data = analytics.geo_traffic(traffic, located(home=None), after=0)
    assert data["home"] is None and data["placed"] == 0 and data["arcs"] == []


def test_cursor_starts_now_and_recovers_from_future_ids(traffic):
    assert analytics.geo_traffic(traffic, located(), after=None) == {
        "home": {"lat": HOME[0], "lon": HOME[1], "country": "LAN", "name": "Réseau local", "city": ""},
        "geo": "off", "note": "désactivée", "last_id": 4, "arcs": [], "packets": 0, "placed": 0}
    assert analytics.geo_traffic(traffic, located(), after=999)["last_id"] == 4


def test_offline_database_provides_coordinates():
    class Reader:
        @staticmethod
        def get(ip):
            return {"country": {"iso_code": "FR", "names": {"fr": "France"}}, "city": {"names": {"fr": "Paris"}},
                    "continent": {"code": "EU"}, "location": {"latitude": 48.86, "longitude": 2.34}}

    geo = GeoResolver("off")
    geo._reader = Reader()
    info = geo._lookup_offline("1.2.3.4")
    assert (info.country, info.city, info.lat, info.lon, info.located) == ("FR", "Paris", 48.86, 2.34, True)


def test_home_option_is_validated():
    assert build_parser().parse_args(["--home", "48.85,2.35"]).home == HOME
    for bad in ("48.85", "nord,est", "95,0", "0,200"):
        with pytest.raises(SystemExit):
            build_parser().parse_args(["--home", bad])


def test_api_and_static_files(frames):
    engine = Engine(EngineConfig())
    feed(engine, frames.syn())
    server = Api(engine, located(), port=0, token="t0ken").start()
    base = "http://{}:{}".format(*server.address)
    try:
        assert requests.get(base + "/api/geo/traffic", timeout=5).status_code == 401
        auth = {"Authorization": "Bearer t0ken"}
        assert requests.get(base + "/api/geo/traffic", headers=auth, timeout=5).json()["last_id"] == 1
        data = requests.get(base + "/api/geo/traffic", params={"after": 0}, headers=auth, timeout=5).json()
        assert [a["direction"] for a in data["arcs"]] == ["out"]

        land = requests.get(base + "/land.json", timeout=5)
        dots = json.loads(land.content)["dots"]
        assert land.headers["Content-Type"] == "application/json" and len(dots) > 1000 and len(dots) % 2 == 0
        assert all(-90 <= lat <= 90 and -180 <= lon <= 180 for lat, lon in zip(dots[::2], dots[1::2], strict=True))
        assert "class Globe" in requests.get(base + "/globe.js", timeout=5).text

        flag = requests.get(base + "/flags/fr.svg", timeout=5)
        assert flag.status_code == 200 and flag.headers["Content-Type"] == "image/svg+xml" and b"<svg" in flag.content
        assert requests.get(base + "/flags/zz.svg", timeout=5).status_code == 404
        assert requests.get(base + "/flags/FR.svg", timeout=5).status_code == 401   # hors motif : route protégée
    finally:
        server.stop()
        engine.close()

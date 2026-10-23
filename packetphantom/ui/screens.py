"""Écrans modaux : suivi de flux, choix d'interface, filtre BPF, ouverture, export, aide."""
from __future__ import annotations

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import ModalScreen
from textual.widgets import Input, Label, Markdown, OptionList, RichLog, Static
from textual.widgets.option_list import Option

from .. import export
from ..capture import CaptureError, validate_bpf
from ..flows import Conversation
from ..layers import hexdump
from .theme import fmt_bytes
from .widgets import palette_of


class Dialog(ModalScreen):
    BINDINGS = [Binding("escape", "dismiss(None)", "Fermer")]


class FollowStreamScreen(Dialog):
    """Conversation reconstituée (déchiffrée si possible), client et serveur colorés."""

    BINDINGS = [
        Binding("escape,q", "dismiss(None)", "Fermer"),
        Binding("h", "toggle_hex", "ASCII / Hex"),
        Binding("d", "toggle_decrypted", "Clair / chiffré"),
        Binding("s", "save", "Enregistrer"),
        Binding("g", "filter", "Filtrer ce flux"),
    ]

    def __init__(self, conv: Conversation):
        super().__init__()
        self.conv = conv
        self.hex_mode = False
        self.show_plain = conv.plaintext is not None

    @property
    def chunks(self) -> list[tuple[bool, bytes]]:
        return self.conv.plaintext if self.show_plain else self.conv.chunks

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog wide"):
            yield Static(id="follow-head")
            yield RichLog(id="follow-log", wrap=True, max_lines=20_000)
            yield Label("H  ASCII/Hex    D  clair/chiffré    S  enregistrer    G  filtrer ce flux    Échap  fermer",
                        classes="dialog-hint")

    def on_mount(self) -> None:
        self.query_one(".dialog").border_title = f"Suivi du flux #{self.conv.flow.id}"
        self.render_stream()

    def _header(self, pal) -> Text:
        f = self.conv.flow
        sent = sum(len(d) for c, d in self.chunks if c)
        received = sum(len(d) for c, d in self.chunks if not c)
        head = Text()
        head.append(f"{f.app or f.l4}  ", style=f"bold {pal.proto_color(f.app or f.l4)}")
        head.append(f"{f.client}:{f.cport}", style=f"bold {pal.client}")
        head.append(f"  → {fmt_bytes(sent)}   ", style=pal.muted)
        head.append(f"{f.server}:{f.sport}", style=f"bold {pal.server}")
        head.append(f"  → {fmt_bytes(received)}", style=pal.muted)
        if f.label:
            head.append(f"   {f.label}", style=pal.accent)
        if self.conv.note:
            ok = self.conv.plaintext is not None
            head.append(f"\n{self.conv.note}" + ("" if self.show_plain or not ok else "  (vue chiffrée)"),
                        style=pal.good if ok else pal.sev[2])
        return head

    def _lines(self, data: bytes, color: str, pal) -> list[Text]:
        if not self.hex_mode:
            text = data[:262_144].decode("utf-8", errors="replace").replace("\r\n", "\n")
            return [Text("".join(ch if ch in "\n\t" or ch.isprintable() else "·" for ch in text), style=color)]
        lines = []
        for offset, hexpart, ascii_part in hexdump(data, limit=65_536):
            line = Text(f"{offset}  ", style=pal.dim)
            line.append(f"{hexpart:<49}", style=color)
            line.append(f" {ascii_part}", style=pal.muted)
            lines.append(line)
        return lines

    def render_stream(self) -> None:
        pal = palette_of(self)
        self.query_one("#follow-head", Static).update(self._header(pal))
        log = self.query_one("#follow-log", RichLog)
        log.clear()
        if not self.chunks:
            log.write(Text("Aucune donnée applicative dans les paquets conservés pour ce flux.", style=pal.muted))
            return
        for is_client, data in self.chunks:
            for line in self._lines(data, pal.client if is_client else pal.server, pal):
                log.write(line)

    def action_toggle_hex(self) -> None:
        self.hex_mode = not self.hex_mode
        self.render_stream()

    def action_toggle_decrypted(self) -> None:
        if self.conv.plaintext is not None:
            self.show_plain = not self.show_plain
            self.render_stream()

    def action_save(self) -> None:
        self.notify(f"Flux enregistré : {export.conversation_raw(self.conv)}", markup=False)

    def action_filter(self) -> None:
        self.dismiss(f"flow == {self.conv.flow.id}")


class InterfaceScreen(Dialog):
    def __init__(self, interfaces: list[str], current: str):
        super().__init__()
        self.interfaces = interfaces
        self.current = current

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog"):
            yield OptionList(*[Option(("● " if i == self.current else "  ") + i, id=i) for i in self.interfaces])
            yield Label("Entrée  sélectionner    Échap  annuler", classes="dialog-hint")

    def on_mount(self) -> None:
        self.query_one(".dialog").border_title = "Interface de capture"
        options = self.query_one(OptionList)
        if self.current in self.interfaces:
            options.highlighted = self.interfaces.index(self.current)

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        self.dismiss(event.option.id)


class PromptScreen(Dialog):
    """Saisie validée (filtre BPF, chemin de fichier)."""

    def __init__(self, title: str, value: str, placeholder: str, hint: str, validator):
        super().__init__()
        self.title_text = title
        self.value = value
        self.placeholder = placeholder
        self.hint = hint
        self.validator = validator

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog"):
            yield Input(self.value, placeholder=self.placeholder, id="prompt-input")
            yield Static(self.hint, id="prompt-msg", classes="dialog-hint")

    def on_mount(self) -> None:
        self.query_one(".dialog").border_title = self.title_text
        self.query_one(Input).focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        value = event.value.strip()
        try:
            self.validator(value)
        except (CaptureError, ValueError) as exc:
            msg = self.query_one("#prompt-msg", Static)
            msg.update(Text(str(exc), style=palette_of(self).sev[4]))
            return
        self.dismiss(value)


def bpf_prompt(current: str, iface: str | None) -> PromptScreen:
    return PromptScreen(
        "Filtre de capture (BPF)", current, "ex. tcp port 443 or udp port 53",
        "Appliqué par le noyau avant l'analyse. Vide = tout capturer. Entrée pour valider.",
        lambda v: validate_bpf(v, iface),
    )


def open_prompt() -> PromptScreen:
    from pathlib import Path

    def check(path: str) -> None:
        if not path or not Path(path).expanduser().is_file():
            raise ValueError(f"Fichier introuvable : {path}")

    return PromptScreen("Ouvrir une capture", "", "chemin/vers/capture.pcap(ng)",
                        "Formats pcap et pcapng. L'analyse remplace la session courante.", check)


EXPORTS = [
    ("pcap-view", "Paquets affichés  →  PCAP"),
    ("pcap-all", "Tous les paquets conservés  →  PCAP"),
    ("csv-view", "Paquets affichés  →  CSV"),
    ("flows", "Flux  →  CSV"),
    ("hosts", "Hôtes  →  NDJSON"),
    ("alerts", "Alertes  →  NDJSON"),
]


class ExportScreen(Dialog):
    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog"):
            yield OptionList(*[Option(label, id=key) for key, label in EXPORTS])
            yield Label("Fichiers écrits dans ./exports/", classes="dialog-hint")

    def on_mount(self) -> None:
        self.query_one(".dialog").border_title = "Exporter"

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        self.dismiss(event.option.id)


HELP = """\
## Raccourcis

| Touche | Action | Touche | Action |
|---|---|---|---|
| `s` | Démarrer / arrêter la capture | `/` | Filtre d'affichage |
| `i` | Choisir l'interface | `b` | Filtre de capture (BPF) |
| `o` | Ouvrir un fichier pcap | `e` | Exporter |
| `f` | Suivre le flux (déchiffré si keylog) | `g` | Filtrer la conversation |
| `p` | Figer / reprendre l'affichage | `c` | Effacer la session |
| `1`-`5` | Changer d'onglet | `t` | Thème sombre / clair |
| `Entrée` | Pivot : flux / hôte / alerte → paquets | `Échap` | Quitter le filtre / l'effacer |
| `?` | Cette aide | `q` | Quitter |

## Filtre d'affichage

```
tls or dns                       protocoles
ip.addr == 10.0.0.0/8            adresse ou réseau CIDR (ip.src, ip.dst)
port 443   ·   tcp.port == 22    ports (udp.port, sport, dport)
domain contains "google"         SNI / Host HTTP / requête DNS (sni, http.host, dns.qry)
info ~ "(?i)pass|login"          expression régulière
len > 1000 and ttl < 64          numériques : == != > < >= <=
tcp.port in {80 443 8080}        ensemble de valeurs
flow == 12                       une conversation
alert >= high                    paquets ayant déclenché une alerte
ja4 == t13d…   ja3 == …         empreintes TLS
eth.src == aa:bb:…               adresses MAC
"texte libre"                    recherche dans toutes les colonnes
```

Opérateurs logiques : `and` `&&` `or` `||` `not` `!` et parenthèses.
"""


class HelpScreen(Dialog):
    BINDINGS = [Binding("escape,q,question_mark", "dismiss(None)", "Fermer")]

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog wide"):
            yield Markdown(HELP)

    def on_mount(self) -> None:
        self.query_one(".dialog").border_title = "Aide - PacketPhantom"

"""Sources de trames : interface réseau (brut, sans dissection) ou fichier de capture."""
from __future__ import annotations

import contextlib
import threading
import time
from collections.abc import Callable
from pathlib import Path

from . import pcapio

Sink = Callable[[bytes, float, int], None]


class CaptureError(RuntimeError):
    pass


def validate_bpf(expression: str, iface: str | None = None) -> None:
    """Lève CaptureError si l'expression BPF ne compile pas."""
    if not expression:
        return
    from scapy.arch.common import compile_filter
    try:
        compile_filter(expression, iface=iface)
    except Exception as exc:
        raise CaptureError(f"Filtre BPF invalide : {expression}") from exc


def list_interfaces() -> list[str]:
    from scapy.interfaces import get_if_list
    return sorted(get_if_list())


def default_interface() -> str:
    from scapy.config import conf
    return str(conf.iface)


class Source:
    """Thread producteur : lit des trames et les pousse vers `sink` jusqu'à `stop()`."""

    name = "source"

    def __init__(self, sink: Sink):
        self.sink = sink
        self.error: str | None = None
        self.finished = False
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._open()
        self._thread = threading.Thread(target=self._guarded_run, name=self.name, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None and self._thread is not threading.current_thread():
            self._thread.join(timeout=2)
        self._close()

    def _guarded_run(self) -> None:
        try:
            self._run()
        except Exception as exc:
            self.error = str(exc) or type(exc).__name__
        finally:
            self.finished = True

    def _open(self) -> None:
        pass

    def _close(self) -> None:
        pass

    def _run(self) -> None:
        raise NotImplementedError


class LiveSource(Source):
    """Socket de capture Scapy (BPF noyau sous Linux, Npcap sous Windows) en lecture brute."""

    name = "capture"

    def __init__(self, sink: Sink, iface: str, bpf: str = ""):
        super().__init__(sink)
        self.iface = iface
        self.bpf = bpf
        self._socket = None

    def _open(self) -> None:
        import scapy.layers.all  # noqa: F401  (enregistre les types de lien)
        from scapy.config import conf
        validate_bpf(self.bpf, self.iface)
        try:
            self._socket = conf.L2listen(iface=self.iface, filter=self.bpf or None)
        except PermissionError as exc:
            raise CaptureError("Permission refusée : lancez avec sudo ou donnez CAP_NET_RAW à Python (voir README)") from exc
        except OSError as exc:
            raise CaptureError(f"Impossible d'ouvrir {self.iface} : {exc}") from exc

    def _close(self) -> None:
        if self._socket is not None:
            with contextlib.suppress(OSError):
                self._socket.close()
            self._socket = None

    def _run(self) -> None:
        from scapy.config import conf
        sock = self._socket
        linktypes: dict[type, int] = {}
        while not self._stop.is_set():
            if not type(sock).select([sock], 0.2):
                continue
            cls, data, ts = sock.recv_raw(65_535)
            if data is None:
                continue
            linktype = linktypes.get(cls)
            if linktype is None:
                linktype = linktypes[cls] = conf.l2types.layer2num.get(cls, 1)
            self.sink(data, ts or time.time(), linktype)


class FileSource(Source):
    """Fichier pcap / pcapng, à pleine vitesse ou au rythme d'origine."""

    name = "pcap-reader"

    def __init__(self, sink: Sink, path: str, realtime: bool = False):
        super().__init__(sink)
        self.path = path
        self.realtime = realtime

    def _open(self) -> None:
        if not Path(self.path).is_file():
            raise CaptureError(f"Fichier introuvable : {self.path}")

    def _run(self) -> None:
        previous = None
        for data, ts, linktype in pcapio.read(self.path):
            if self._stop.is_set():
                return
            if self.realtime and previous is not None and ts > previous:
                self._stop.wait(min(ts - previous, 1.0))
            previous = ts
            self.sink(data, ts, linktype)

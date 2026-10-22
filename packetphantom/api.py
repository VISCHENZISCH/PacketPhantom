"""API REST, flux temps réel (Server-Sent Events) et tableau de bord web.

Toutes les routes /api/* exigent le jeton (en-tête `Authorization: Bearer …`
ou paramètre `?token=…` pour EventSource). Les fichiers statiques sont publics.
"""
from __future__ import annotations

import json
import re
import secrets
import threading
import time
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from typing import NamedTuple
from urllib.parse import parse_qsl, urlsplit

from . import analytics, pcapio, serialize
from .capture import CaptureError, list_interfaces
from .engine import Engine
from .filters import FilterError, compile_filter
from .geoip import GeoResolver
from .layers import hexdump, layer_tree

MAX_BODY = 65_536
STATIC = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
}
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'",
}


class ApiError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


class Request(NamedTuple):
    query: dict[str, str]
    body: dict

    def int(self, name: str, default: int, maximum: int | None = None) -> int:
        try:
            value = int(self.query.get(name, default))
        except ValueError as exc:
            raise ApiError(400, f"Paramètre {name} : entier attendu") from exc
        return min(value, maximum) if maximum is not None else value


class File(NamedTuple):
    body: bytes
    content_type: str
    filename: str


class EventStream:
    """Marqueur : la route bascule la connexion en flux SSE."""


Handler = Callable[..., object]
ROUTES: list[tuple[str, re.Pattern, Handler]] = []


def route(method: str, pattern: str) -> Callable[[Handler], Handler]:
    def register(fn: Handler) -> Handler:
        ROUTES.append((method, re.compile(f"^{pattern}$"), fn))
        return fn
    return register


# ====================================================================== routes

def _filtered_packets(api: Api, req: Request):
    try:
        predicate = compile_filter(req.query.get("filter", ""))
    except FilterError as exc:
        raise ApiError(400, str(exc)) from exc
    packets = api.engine.snapshot_packets()
    return [p for p in packets if predicate(p)] if predicate else packets


def _sorted(items: list, req: Request, keys: dict[str, Callable], default: str) -> list:
    key = keys.get(req.query.get("sort", default), keys[default])
    return sorted(items, key=key, reverse=req.query.get("order", "desc") != "asc")


@route("GET", "/api/status")
def status(api: Api, req: Request) -> dict:
    return analytics.status(api.engine, api.geo)


@route("GET", "/api/analytics")
def rankings(api: Api, req: Request) -> dict:
    return analytics.rankings(api.engine, api.geo, req.int("limit", 10, 100))


@route("GET", "/api/interfaces")
def interfaces(api: Api, req: Request) -> dict:
    return {"interfaces": list_interfaces()}


@route("GET", "/api/packets")
def packets(api: Api, req: Request) -> dict:
    matched = _filtered_packets(api, req)[-req.int("limit", 300, 5000):]
    return {"items": [serialize.packet(p) for p in matched], "last_id": api.engine.last_packet_id}


@route("GET", r"/api/packets/(\d+)")
def packet_detail(api: Api, req: Request, pid: str) -> dict:
    pkt = api.engine.get_packet(int(pid))
    if pkt is None:
        raise ApiError(404, "Paquet absent du tampon")
    return {
        **serialize.packet(pkt),
        "application": serialize.application(pkt),
        "layers": [{"name": layer.name, "fields": layer.fields} for layer in layer_tree(pkt)],
        "hex": hexdump(pkt.data),
        "alerts": [serialize.alert(a) for a in api.engine.alerts_for_packet(pkt.id)],
    }


@route("GET", "/api/flows")
def flows(api: Api, req: Request) -> dict:
    with api.engine.lock:
        items = api.engine.flows.values()
    items = _sorted(items, req, {"bytes": lambda f: f.bytes, "packets": lambda f: f.packets,
                                 "last": lambda f: f.last, "duration": lambda f: f.duration}, "last")
    return {"items": [serialize.flow(f, api.geo) for f in items[:req.int("limit", 500, 5000)]]}


@route("GET", r"/api/flows/(\d+)/conversation")
def conversation(api: Api, req: Request, flow_id: str) -> dict:
    conv = api.engine.conversation(int(flow_id))
    if conv is None:
        raise ApiError(404, "Flux inconnu")
    return serialize.conversation(conv)


@route("GET", "/api/hosts")
def hosts(api: Api, req: Request) -> dict:
    with api.engine.lock:
        items = api.engine.hosts.values()
    items = _sorted(items, req, {"bytes": lambda h: h.bytes, "last": lambda h: h.last,
                                 "peers": lambda h: len(h.peers)}, "bytes")
    return {"items": [serialize.host(h, api.geo) for h in items[:req.int("limit", 500, 5000)]]}


@route("GET", "/api/alerts")
def alerts(api: Api, req: Request) -> dict:
    items = api.engine.alerts_after(req.int("after", 0), req.int("limit", 500, 10_000))
    return {"items": [serialize.alert(a) for a in items], "last_id": api.engine.last_alert_id}


@route("GET", "/api/export.pcap")
def export_pcap(api: Api, req: Request) -> File:
    body = pcapio.dumps((p.data, p.ts, p.linktype) for p in _filtered_packets(api, req))
    return File(body, "application/vnd.tcpdump.pcap", f"packetphantom-{time.strftime('%Y%m%d-%H%M%S')}.pcap")


@route("POST", "/api/capture")
def capture(api: Api, req: Request) -> dict:
    action = req.body.get("action")
    if action == "stop":
        api.engine.stop()
    elif action == "start":
        try:
            api.engine.start_live(req.body.get("iface") or None, req.body.get("bpf") or "")
        except CaptureError as exc:
            raise ApiError(409, str(exc)) from exc
    else:
        raise ApiError(400, "action attendue : start ou stop")
    return analytics.status(api.engine, api.geo)


@route("GET", "/api/events")
def events(api: Api, req: Request) -> EventStream:
    return EventStream()


# ====================================================================== serveur

class _Handler(BaseHTTPRequestHandler):
    server_version = "PacketPhantom"
    protocol_version = "HTTP/1.1"

    def log_message(self, *args) -> None:
        pass

    def do_GET(self) -> None:
        self._dispatch("GET")

    def do_POST(self) -> None:
        self._dispatch("POST")

    @property
    def api(self) -> Api:
        return self.server.api  # type: ignore[attr-defined]

    def _dispatch(self, method: str) -> None:
        url = urlsplit(self.path)
        query = dict(parse_qsl(url.query))
        if method == "GET" and url.path in STATIC:
            name, content_type = STATIC[url.path]
            return self._send(200, (resources.files(__package__) / "web" / name).read_bytes(), content_type)
        if not self._authorized(query):
            return self._json(401, {"error": "Jeton d'API manquant ou invalide"})
        for route_method, pattern, handler in ROUTES:
            match = pattern.match(url.path)
            if match and route_method == method:
                return self._call(handler, method, query, match.groups())
        self._json(404, {"error": f"Route inconnue : {method} {url.path}"})

    def _call(self, handler: Handler, method: str, query: dict[str, str], args: tuple) -> None:
        try:
            req = Request(query, self._body() if method == "POST" else {})
            result = handler(self.api, req, *args)
        except ApiError as exc:
            return self._json(exc.status, {"error": exc.message})
        if isinstance(result, EventStream):
            return self._stream()
        if isinstance(result, File):
            return self._send(200, result.body, result.content_type,
                              {"Content-Disposition": f'attachment; filename="{result.filename}"'})
        self._json(200, result)

    def _authorized(self, query: dict[str, str]) -> bool:
        header = self.headers.get("Authorization", "")
        supplied = header[7:] if header.startswith("Bearer ") else query.get("token", "")
        return secrets.compare_digest(supplied.encode(), self.api.token.encode())

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if not length:
            return {}
        if length > MAX_BODY:
            raise ApiError(413, "Corps de requête trop volumineux")
        try:
            body = json.loads(self.rfile.read(length))
        except json.JSONDecodeError as exc:
            raise ApiError(400, "JSON invalide") from exc
        return body if isinstance(body, dict) else {}

    def _send(self, status: int, body: bytes, content_type: str, extra: dict | None = None) -> None:
        self.send_response(status)
        for key, value in {**SECURITY_HEADERS, "Content-Type": content_type,
                           "Content-Length": str(len(body)), **(extra or {})}.items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, payload: object) -> None:
        self._send(status, json.dumps(payload, ensure_ascii=False).encode(), "application/json; charset=utf-8")

    def _stream(self) -> None:
        """SSE : `status` chaque seconde, `alert` pour chaque nouvelle alerte."""
        self.send_response(200)
        for key, value in {**SECURITY_HEADERS, "Content-Type": "text/event-stream", "Connection": "keep-alive"}.items():
            self.send_header(key, value)
        self.end_headers()
        api, cursor = self.api, self.api.engine.last_alert_id
        try:
            while not api.stopping.is_set():
                for alert in api.engine.alerts_after(cursor):
                    cursor = alert.id
                    self._event("alert", serialize.alert(alert))
                self._event("status", analytics.status(api.engine, api.geo))
                api.stopping.wait(1.0)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _event(self, name: str, payload: dict) -> None:
        self.wfile.write(f"event: {name}\ndata: {json.dumps(payload, ensure_ascii=False)}\n\n".encode())
        self.wfile.flush()


class Api:
    def __init__(self, engine: Engine, geo: GeoResolver, host: str = "127.0.0.1", port: int = 8787,
                 token: str | None = None):
        self.engine = engine
        self.geo = geo
        self.token = token or secrets.token_urlsafe(18)
        self.stopping = threading.Event()
        self._server = ThreadingHTTPServer((host, port), _Handler)
        self._server.daemon_threads = True
        self._server.api = self  # type: ignore[attr-defined]

    @property
    def address(self) -> tuple[str, int]:
        host, port = self._server.server_address[:2]
        return str(host), int(port)

    @property
    def url(self) -> str:
        host, port = self.address
        return f"http://{host}:{port}/#token={self.token}"

    def start(self) -> Api:
        threading.Thread(target=self._server.serve_forever, name="api", daemon=True).start()
        return self

    def stop(self) -> None:
        self.stopping.set()
        self._server.shutdown()
        self._server.server_close()

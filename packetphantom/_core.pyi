"""Cœur Rust de PacketPhantom : décodage des trames et empreintes TLS."""

__version__: str

class Dns:
    qr: bool
    qname: str
    qtype: str
    rcode: int
    answers: list[tuple[str, str, str]]

class ClientHello:
    version: int
    legacy_version: int
    random: str
    sni: str
    alpn: list[str]
    ciphers: list[int]
    extensions: list[int]
    ja3: str
    ja3_full: str
    ja4: str

class ServerHello:
    version: int
    legacy_version: int
    random: str
    cipher: int
    ja3s: str
    ja3s_full: str

class HttpRequest:
    method: str
    path: str
    version: str
    host: str
    headers: list[tuple[str, str]]
    body: bytes
    def header(self, name: str) -> str | None: ...

class HttpResponse:
    code: int
    reason: str
    version: str
    headers: list[tuple[str, str]]
    def header(self, name: str) -> str | None: ...

class Dhcp:
    msg_type: str
    hostname: str
    requested: str
    client_mac: str

class Arp:
    op: int
    psrc: str
    hwsrc: str
    pdst: str
    hwdst: str

class Packet:
    id: int
    ts: float
    length: int
    linktype: int
    proto: str
    l4: str
    src: str
    dst: str
    sport: int | None
    dport: int | None
    ttl: int | None
    ip_version: int
    smac: str
    dmac: str
    tcp_flags: int
    flags: str
    seq: int
    window: int
    tcp_options: list[str]
    mss: int | None
    info: str
    domain: str
    ja3: str
    ja4: str
    banner: str | None
    malformed: bool
    tls_partial: bool
    flow_id: int
    severity: int
    data: bytes
    payload: bytes
    payload_len: int
    is_syn: bool
    is_synack: bool
    dns: Dns | None
    tls_client: ClientHello | None
    tls_server: ServerHello | None
    http_request: HttpRequest | None
    http_response: HttpResponse | None
    dhcp: Dhcp | None
    arp: Arp | None
    def has(self, name: str) -> bool: ...
    def attach_client_hello(self, hello: ClientHello) -> None: ...
    def __len__(self) -> int: ...

def parse(data: bytes, ts: float, linktype: int = 1) -> Packet: ...
def parse_client_hello(stream: bytes) -> ClientHello | None: ...
def parse_server_hello(stream: bytes) -> ServerHello | None: ...
def service_name(sport: int, dport: int | None = None) -> str | None: ...
def known_protocols() -> list[str]: ...
def tls_version_name(version: int) -> str: ...

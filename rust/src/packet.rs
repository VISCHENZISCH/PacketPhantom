//! Types exposés à Python : un paquet décodé et ses informations applicatives.

use pyo3::prelude::*;
use pyo3::types::PyBytes;

use crate::fmt;

#[pyclass(module = "packetphantom._core", get_all, frozen)]
#[derive(Clone, Debug, Default)]
pub struct Dns {
    pub qr: bool,
    pub qname: String,
    pub qtype: String,
    pub rcode: u8,
    /// (nom, type, valeur)
    pub answers: Vec<(String, String, String)>,
}

#[pyclass(module = "packetphantom._core", get_all, frozen)]
#[derive(Clone, Debug, Default)]
pub struct ClientHello {
    /// Version maximale proposée (extension supported_versions incluse).
    pub version: u16,
    pub legacy_version: u16,
    pub random: String,
    pub sni: String,
    pub alpn: Vec<String>,
    pub ciphers: Vec<u16>,
    pub extensions: Vec<u16>,
    pub ja3: String,
    pub ja3_full: String,
    pub ja4: String,
}

#[pyclass(module = "packetphantom._core", get_all, frozen)]
#[derive(Clone, Debug, Default)]
pub struct ServerHello {
    /// Version négociée (extension supported_versions incluse).
    pub version: u16,
    pub legacy_version: u16,
    pub random: String,
    pub cipher: u16,
    pub ja3s: String,
    pub ja3s_full: String,
}

fn find_header(headers: &[(String, String)], name: &str) -> Option<String> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.clone())
}

#[pyclass(module = "packetphantom._core", frozen)]
#[derive(Clone, Debug, Default)]
pub struct HttpRequest {
    #[pyo3(get)]
    pub method: String,
    #[pyo3(get)]
    pub path: String,
    #[pyo3(get)]
    pub version: String,
    #[pyo3(get)]
    pub host: String,
    /// En-têtes, noms en minuscules.
    #[pyo3(get)]
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

#[pymethods]
impl HttpRequest {
    fn header(&self, name: &str) -> Option<String> {
        find_header(&self.headers, name)
    }

    #[getter]
    fn body<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.body)
    }
}

#[pyclass(module = "packetphantom._core", get_all, frozen)]
#[derive(Clone, Debug, Default)]
pub struct HttpResponse {
    pub code: u16,
    pub reason: String,
    pub version: String,
    pub headers: Vec<(String, String)>,
}

#[pymethods]
impl HttpResponse {
    fn header(&self, name: &str) -> Option<String> {
        find_header(&self.headers, name)
    }
}

#[pyclass(module = "packetphantom._core", get_all, frozen)]
#[derive(Clone, Debug, Default)]
pub struct Dhcp {
    pub msg_type: String,
    pub hostname: String,
    pub requested: String,
    pub client_mac: String,
}

#[pyclass(module = "packetphantom._core", get_all, frozen)]
#[derive(Clone, Debug, Default)]
pub struct Arp {
    pub op: u16,
    pub psrc: String,
    pub hwsrc: String,
    pub pdst: String,
    pub hwdst: String,
}

/// Donnée applicative : au plus une par paquet, allouée seulement si présente.
#[derive(Clone, Debug)]
pub enum App {
    Dns(Dns),
    ClientHello(ClientHello),
    ServerHello(ServerHello),
    HttpRequest(HttpRequest),
    HttpResponse(HttpResponse),
    Dhcp(Dhcp),
    Arp(Arp),
}

#[pyclass(module = "packetphantom._core")]
#[derive(Clone, Debug, Default)]
pub struct Packet {
    #[pyo3(get, set)]
    pub id: u64,
    #[pyo3(get)]
    pub ts: f64,
    #[pyo3(get)]
    pub length: usize,
    #[pyo3(get)]
    pub linktype: u32,
    /// Protocole le plus spécifique (TLS, DNS, HTTP, SSH…).
    #[pyo3(get)]
    pub proto: &'static str,
    /// Couche transport (TCP, UDP, ICMP, ARP…).
    #[pyo3(get)]
    pub l4: &'static str,
    #[pyo3(get)]
    pub src: String,
    #[pyo3(get)]
    pub dst: String,
    #[pyo3(get)]
    pub sport: Option<u16>,
    #[pyo3(get)]
    pub dport: Option<u16>,
    #[pyo3(get)]
    pub ttl: Option<u8>,
    #[pyo3(get)]
    pub ip_version: u8,
    #[pyo3(get)]
    pub smac: String,
    #[pyo3(get)]
    pub dmac: String,
    #[pyo3(get)]
    pub tcp_flags: u8,
    #[pyo3(get)]
    pub seq: u32,
    #[pyo3(get)]
    pub window: u16,
    /// Ordre des options TCP (SYN uniquement), noms compatibles p0f/Scapy.
    #[pyo3(get)]
    pub tcp_options: Vec<&'static str>,
    #[pyo3(get)]
    pub mss: Option<u16>,
    #[pyo3(get)]
    pub info: String,
    #[pyo3(get)]
    pub domain: String,
    #[pyo3(get)]
    pub ja3: String,
    #[pyo3(get)]
    pub ja4: String,
    #[pyo3(get)]
    pub banner: Option<String>,
    #[pyo3(get)]
    pub malformed: bool,
    /// ClientHello tronqué : à réassembler avec les segments suivants.
    #[pyo3(get)]
    pub tls_partial: bool,
    #[pyo3(get, set)]
    pub flow_id: u64,
    #[pyo3(get, set)]
    pub severity: i8,
    pub app: Option<Box<App>>,
    pub data: Vec<u8>,
    pub payload_offset: usize,
    pub payload_len: usize,
}

/// Accesseurs Python vers la donnée applicative (`None` si le paquet n'en porte pas).
macro_rules! app_getters {
    ($($name:ident => $variant:ident),* $(,)?) => {
        #[pymethods]
        impl Packet {
            $(
                #[getter]
                fn $name(&self) -> Option<$variant> {
                    match self.app.as_deref() {
                        Some(App::$variant(v)) => Some(v.clone()),
                        _ => None,
                    }
                }
            )*
        }
    };
}

app_getters!(
    dns => Dns,
    tls_client => ClientHello,
    tls_server => ServerHello,
    http_request => HttpRequest,
    http_response => HttpResponse,
    dhcp => Dhcp,
    arp => Arp,
);

impl Packet {
    pub fn new(data: &[u8], ts: f64, linktype: u32) -> Self {
        Self {
            ts,
            linktype,
            length: data.len(),
            data: data.to_vec(),
            proto: "?",
            severity: -1,
            ..Default::default()
        }
    }

    pub fn set_app(&mut self, app: App) {
        self.app = Some(Box::new(app));
    }

    pub fn set_payload(&mut self, start: usize, end: usize) {
        self.payload_offset = start.min(self.data.len());
        self.payload_len = end.min(self.data.len()).saturating_sub(self.payload_offset);
    }

    pub fn payload_slice(&self) -> &[u8] {
        &self.data[self.payload_offset..self.payload_offset + self.payload_len]
    }

    pub fn mark_malformed(&mut self, what: &str) {
        self.malformed = true;
        if self.info.is_empty() {
            self.info = format!("{what} malformé");
        }
    }

    /// Applique un ClientHello (décodé directement ou après réassemblage).
    pub fn apply_client_hello(&mut self, ch: ClientHello) {
        self.proto = "TLS";
        self.tls_partial = false;
        self.domain = ch.sni.clone();
        self.ja3 = ch.ja3.clone();
        self.ja4 = ch.ja4.clone();
        let sni = if ch.sni.is_empty() { "-" } else { &ch.sni };
        self.info = format!("Client Hello  SNI={sni}  {}", crate::app::tls::version_name(ch.version));
        self.set_app(App::ClientHello(ch));
    }
}

#[pymethods]
impl Packet {
    #[getter]
    fn data<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.data)
    }

    #[getter]
    fn payload<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.payload_slice())
    }

    #[getter]
    fn payload_len(&self) -> usize {
        self.payload_len
    }

    #[getter]
    fn flags(&self) -> String {
        fmt::tcp_flags(self.tcp_flags)
    }

    #[getter]
    fn is_syn(&self) -> bool {
        self.l4 == "TCP" && self.tcp_flags & (fmt::SYN | fmt::ACK) == fmt::SYN
    }

    #[getter]
    fn is_synack(&self) -> bool {
        self.l4 == "TCP" && self.tcp_flags & (fmt::SYN | fmt::ACK) == fmt::SYN | fmt::ACK
    }

    /// Le paquet porte-t-il ce protocole / cette étiquette (insensible à la casse) ?
    fn has(&self, name: &str) -> bool {
        let app = match self.app.as_deref() {
            Some(App::HttpRequest(_) | App::HttpResponse(_)) => "http",
            Some(App::ClientHello(_) | App::ServerHello(_)) => "tls",
            _ => "",
        };
        let ip: &[&str] = match self.ip_version {
            4 => &["ip", "ipv4"],
            6 => &["ipv6"],
            _ => &[],
        };
        let eth = if self.smac.is_empty() { "" } else { "eth" };
        let malformed = if self.malformed { "malformed" } else { "" };
        [self.proto, self.l4, app, eth, malformed]
            .iter()
            .chain(ip)
            .any(|tag| !tag.is_empty() && tag.eq_ignore_ascii_case(name))
    }

    /// Rattache un ClientHello obtenu par réassemblage TCP.
    fn attach_client_hello(&mut self, hello: ClientHello) {
        self.apply_client_hello(hello);
    }

    fn __len__(&self) -> usize {
        self.length
    }

    fn __repr__(&self) -> String {
        format!("<Packet #{} {} {} → {} {}>", self.id, self.proto, self.src, self.dst, self.info)
    }
}

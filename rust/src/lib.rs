//! PacketPhantom — cœur de décodage réseau, exposé à Python sous `packetphantom._core`.

mod app;
mod decode;
mod fmt;
mod packet;
mod reader;
mod services;

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

use app::tls::{self, HelloError};
use packet::{Arp, ClientHello, Dhcp, Dns, HttpRequest, HttpResponse, Packet, ServerHello};

/// Décode une trame brute. Le GIL est relâché pendant le décodage.
#[pyfunction]
#[pyo3(signature = (data, ts, linktype = 1))]
fn parse(py: Python<'_>, data: &[u8], ts: f64, linktype: u32) -> Packet {
    py.allow_threads(|| decode::decode(data, ts, linktype))
}

fn hello_result<T>(result: Result<T, HelloError>) -> PyResult<Option<T>> {
    match result {
        Ok(hello) => Ok(Some(hello)),
        Err(HelloError::Incomplete) => Ok(None),
        Err(HelloError::Invalid) => Err(PyValueError::new_err("handshake TLS invalide")),
    }
}

/// ClientHello depuis un flux d'enregistrements TLS ; None si le flux est encore incomplet.
#[pyfunction]
fn parse_client_hello(stream: &[u8]) -> PyResult<Option<ClientHello>> {
    hello_result(tls::parse_client_hello(stream))
}

/// ServerHello depuis un flux d'enregistrements TLS ; None si le flux est encore incomplet.
#[pyfunction]
fn parse_server_hello(stream: &[u8]) -> PyResult<Option<ServerHello>> {
    hello_result(tls::parse_server_hello(stream))
}

#[pyfunction]
#[pyo3(signature = (sport, dport = None))]
fn service_name(sport: u16, dport: Option<u16>) -> Option<&'static str> {
    match dport {
        Some(d) => services::lookup(sport, d),
        None => services::by_port(sport),
    }
}

/// Noms de protocoles connus (en minuscules), pour le langage de filtre.
#[pyfunction]
fn known_protocols() -> Vec<String> {
    let mut names: Vec<String> = services::SERVICES
        .iter()
        .map(|(_, n)| *n)
        .chain(services::PROTOCOLS.iter().copied())
        .map(str::to_ascii_lowercase)
        .collect();
    names.sort();
    names.dedup();
    names
}

#[pyfunction]
fn tls_version_name(version: u16) -> String {
    tls::version_name(version)
}

#[pymodule]
fn _core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add_class::<Packet>()?;
    m.add_class::<Dns>()?;
    m.add_class::<ClientHello>()?;
    m.add_class::<ServerHello>()?;
    m.add_class::<HttpRequest>()?;
    m.add_class::<HttpResponse>()?;
    m.add_class::<Dhcp>()?;
    m.add_class::<Arp>()?;
    m.add_function(wrap_pyfunction!(parse, m)?)?;
    m.add_function(wrap_pyfunction!(parse_client_hello, m)?)?;
    m.add_function(wrap_pyfunction!(parse_server_hello, m)?)?;
    m.add_function(wrap_pyfunction!(service_name, m)?)?;
    m.add_function(wrap_pyfunction!(known_protocols, m)?)?;
    m.add_function(wrap_pyfunction!(tls_version_name, m)?)?;
    Ok(())
}

//! TLS : ClientHello / ServerHello, empreintes JA3, JA3S et JA4.
//! Les messages handshake fragmentés sur plusieurs enregistrements sont réassemblés.

use md5::Md5;
use sha2::{Digest, Sha256};

use crate::fmt::{hex, is_grease, join};
use crate::packet::{App, ClientHello, Packet, ServerHello};
use crate::reader::Reader;

const HANDSHAKE: u8 = 22;
const CLIENT_HELLO: u8 = 1;
const SERVER_HELLO: u8 = 2;

const EXT_SNI: u16 = 0;
const EXT_GROUPS: u16 = 10;
const EXT_POINT_FORMATS: u16 = 11;
const EXT_SIG_ALGS: u16 = 13;
const EXT_ALPN: u16 = 16;
const EXT_VERSIONS: u16 = 43;

#[derive(Debug, PartialEq, Eq)]
pub enum HelloError {
    /// Données insuffisantes : attendre les segments suivants.
    Incomplete,
    Invalid,
}

pub fn version_name(v: u16) -> String {
    match v {
        0x0300 => "SSL 3.0".into(),
        0x0301 => "TLS 1.0".into(),
        0x0302 => "TLS 1.1".into(),
        0x0303 => "TLS 1.2".into(),
        0x0304 => "TLS 1.3".into(),
        other => format!("0x{other:04x}"),
    }
}

fn record_name(content_type: u8) -> &'static str {
    match content_type {
        20 => "Change Cipher Spec",
        21 => "Alerte",
        22 => "Handshake",
        _ => "Données applicatives",
    }
}

fn handshake_name(t: u8) -> &'static str {
    match t {
        4 => "New Session Ticket",
        8 => "Encrypted Extensions",
        11 => "Certificate",
        12 => "Server Key Exchange",
        13 => "Certificate Request",
        14 => "Server Hello Done",
        16 => "Client Key Exchange",
        _ => "chiffré",
    }
}

/// Premier message handshake d'un flux d'enregistrements TLS : (type, corps).
fn first_handshake(stream: &[u8]) -> Result<(u8, Vec<u8>), HelloError> {
    let mut r = Reader::new(stream);
    let mut buf = Vec::new();
    loop {
        let (Some(content_type), Some(major), Some(_minor), Some(len)) = (r.u8(), r.u8(), r.u8(), r.u16()) else {
            return Err(HelloError::Incomplete);
        };
        if content_type != HANDSHAKE || major != 3 {
            return Err(HelloError::Invalid);
        }
        let len = usize::from(len);
        let available = r.remaining();
        buf.extend_from_slice(r.take(len.min(available)).unwrap_or_default());
        if buf.len() >= 4 {
            let hs_len = u32::from_be_bytes([0, buf[1], buf[2], buf[3]]) as usize;
            if buf.len() >= 4 + hs_len {
                return Ok((buf[0], buf[4..4 + hs_len].to_vec()));
            }
        }
        if len > available {
            return Err(HelloError::Incomplete);
        }
    }
}

fn digest_hex<D: Digest>(input: &str) -> String {
    hex(&D::digest(input.as_bytes()))
}

fn non_grease(values: &[u16]) -> Vec<u16> {
    values.iter().copied().filter(|v| !is_grease(*v)).collect()
}

pub fn parse_client_hello(stream: &[u8]) -> Result<ClientHello, HelloError> {
    match first_handshake(stream)? {
        (CLIENT_HELLO, body) => client_hello(&body).ok_or(HelloError::Invalid),
        _ => Err(HelloError::Invalid),
    }
}

pub fn parse_server_hello(stream: &[u8]) -> Result<ServerHello, HelloError> {
    match first_handshake(stream)? {
        (SERVER_HELLO, body) => server_hello(&body).ok_or(HelloError::Invalid),
        _ => Err(HelloError::Invalid),
    }
}

fn client_hello(body: &[u8]) -> Option<ClientHello> {
    let mut r = Reader::new(body);
    let legacy = r.u16()?;
    let random = r.take(32)?;
    r.vec8()?;
    let ciphers = r.vec16()?.u16_list();
    r.vec8()?;

    let mut ch = ClientHello { legacy_version: legacy, version: legacy, random: hex(random), ciphers, ..Default::default() };
    let (mut groups, mut point_formats, mut sig_algs) = (Vec::new(), Vec::new(), Vec::new());
    if let Some(mut exts) = r.vec16() {
        while let (Some(kind), Some(data)) = (exts.u16(), exts.vec16()) {
            ch.extensions.push(kind);
            match kind {
                EXT_SNI => {
                    ch.sni = Some(data).and_then(|mut d: Reader<'_>| {
                        let mut list = d.vec16()?;
                        list.u8()?;
                        Some(String::from_utf8_lossy(list.vec16()?.rest()).into_owned())
                    })
                    .unwrap_or_default();
                }
                EXT_GROUPS => groups = Some(data).and_then(|mut d: Reader<'_>| Some(d.vec16()?.u16_list())).unwrap_or_default(),
                EXT_POINT_FORMATS => point_formats = Some(data).and_then(|mut d: Reader<'_>| Some(d.vec8()?.rest().to_vec())).unwrap_or_default(),
                EXT_SIG_ALGS => sig_algs = Some(data).and_then(|mut d: Reader<'_>| Some(d.vec16()?.u16_list())).unwrap_or_default(),
                EXT_ALPN => {
                    ch.alpn = Some(data).and_then(|mut d: Reader<'_>| {
                        let mut list = d.vec16()?;
                        let mut out = Vec::new();
                        while let Some(mut proto) = list.vec8() {
                            out.push(String::from_utf8_lossy(proto.rest()).into_owned());
                        }
                        Some(out)
                    })
                    .unwrap_or_default();
                }
                EXT_VERSIONS => {
                    if let Some(max) = Some(data).and_then(|mut d: Reader<'_>| non_grease(&d.vec8()?.u16_list()).into_iter().max()) {
                        ch.version = max;
                    }
                }
                _ => {}
            }
        }
    }

    ch.ja3_full = format!(
        "{},{},{},{},{}",
        legacy,
        join(&non_grease(&ch.ciphers), "-"),
        join(&non_grease(&ch.extensions), "-"),
        join(&non_grease(&groups), "-"),
        join(&point_formats, "-"),
    );
    ch.ja3 = digest_hex::<Md5>(&ch.ja3_full);
    ch.ja4 = ja4(&ch, &sig_algs);
    Some(ch)
}

/// JA4 (FoxIO) pour TLS sur TCP : t{version}{d|i}{nb suites}{nb ext}{alpn}_{hash suites}_{hash ext+sigalgs}.
fn ja4(ch: &ClientHello, sig_algs: &[u16]) -> String {
    let version = match ch.version {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        _ => "00",
    };
    let sni = if ch.extensions.contains(&EXT_SNI) { 'd' } else { 'i' };
    let ciphers = non_grease(&ch.ciphers);
    let exts = non_grease(&ch.extensions);
    let alpn = match ch.alpn.first().map(String::as_bytes) {
        Some([first, .., last]) if first.is_ascii_alphanumeric() && last.is_ascii_alphanumeric() => {
            format!("{}{}", *first as char, *last as char)
        }
        Some([only]) if only.is_ascii_alphanumeric() => format!("{0}{0}", *only as char),
        Some(value) if !value.is_empty() => {
            let h = hex(value);
            format!("{}{}", &h[..1], &h[h.len() - 1..])
        }
        _ => "00".into(),
    };

    let hash12 = |items: &[String]| -> String {
        if items.is_empty() {
            "000000000000".into()
        } else {
            digest_hex::<Sha256>(&items.join(","))[..12].to_string()
        }
    };
    let as_hex = |v: &u16| format!("{v:04x}");

    let mut sorted_ciphers: Vec<String> = ciphers.iter().map(as_hex).collect();
    sorted_ciphers.sort();
    let mut sorted_exts: Vec<String> =
        exts.iter().filter(|e| !matches!(**e, EXT_SNI | EXT_ALPN)).map(as_hex).collect();
    sorted_exts.sort();
    let ext_hash = if sorted_exts.is_empty() {
        "000000000000".into()
    } else {
        let mut input = sorted_exts.join(",");
        if !sig_algs.is_empty() {
            input.push('_');
            input.push_str(&sig_algs.iter().map(as_hex).collect::<Vec<_>>().join(","));
        }
        digest_hex::<Sha256>(&input)[..12].to_string()
    };
    format!(
        "t{version}{sni}{:02}{:02}{alpn}_{}_{ext_hash}",
        ciphers.len().min(99),
        exts.len().min(99),
        hash12(&sorted_ciphers),
    )
}

fn server_hello(body: &[u8]) -> Option<ServerHello> {
    let mut r = Reader::new(body);
    let legacy = r.u16()?;
    let random = r.take(32)?;
    r.vec8()?;
    let cipher = r.u16()?;
    r.u8()?;
    let mut sh = ServerHello { legacy_version: legacy, version: legacy, random: hex(random), cipher, ..Default::default() };
    let mut types = Vec::new();
    if let Some(mut exts) = r.vec16() {
        while let (Some(kind), Some(mut data)) = (exts.u16(), exts.vec16()) {
            types.push(kind);
            if kind == EXT_VERSIONS {
                if let Some(v) = data.u16() {
                    sh.version = v;
                }
            }
        }
    }
    sh.ja3s_full = format!("{legacy},{cipher},{}", join(&types, "-"));
    sh.ja3s = digest_hex::<Md5>(&sh.ja3s_full);
    Some(sh)
}

/// Annote un paquet TCP dont le payload ressemble à un enregistrement TLS.
pub fn inspect(p: &mut Packet, payload: &[u8]) -> bool {
    if payload.len() < 5 || !(20..=23).contains(&payload[0]) || payload[1] != 3 {
        return false;
    }
    p.proto = "TLS";
    if payload[0] != HANDSHAKE {
        p.info = record_name(payload[0]).into();
        return true;
    }
    match payload.get(5) {
        Some(&CLIENT_HELLO) => match parse_client_hello(payload) {
            Ok(ch) => p.apply_client_hello(ch),
            Err(HelloError::Incomplete) => {
                p.tls_partial = true;
                p.info = "Client Hello (fragmenté)".into();
            }
            Err(HelloError::Invalid) => p.info = "Handshake".into(),
        },
        Some(&SERVER_HELLO) => match parse_server_hello(payload) {
            Ok(sh) => {
                p.info = format!("Server Hello  {}  suite=0x{:04x}", version_name(sh.version), sh.cipher);
                p.set_app(App::ServerHello(sh));
            }
            Err(_) => p.info = "Server Hello".into(),
        },
        Some(&t) => p.info = format!("Handshake {}", handshake_name(t)),
        None => p.info = "Handshake".into(),
    }
    true
}

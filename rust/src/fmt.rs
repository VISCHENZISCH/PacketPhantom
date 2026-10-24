//! Petits formats partagés : MAC, drapeaux TCP, lignes lisibles, hexadécimal.

use std::fmt::Write;

pub fn mac(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(17);
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            out.push(':');
        }
        let _ = write!(out, "{b:02x}");
    }
    out
}

pub fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

pub const FIN: u8 = 0x01;
pub const SYN: u8 = 0x02;
pub const RST: u8 = 0x04;
pub const PSH: u8 = 0x08;
pub const ACK: u8 = 0x10;
pub const URG: u8 = 0x20;
pub const ECE: u8 = 0x40;
pub const CWR: u8 = 0x80;

const FLAG_NAMES: [(u8, &str); 8] = [
    (SYN, "SYN"), (FIN, "FIN"), (RST, "RST"), (PSH, "PSH"),
    (ACK, "ACK"), (URG, "URG"), (ECE, "ECE"), (CWR, "CWR"),
];

pub fn tcp_flags(flags: u8) -> String {
    FLAG_NAMES
        .iter()
        .filter(|(bit, _)| flags & bit != 0)
        .map(|(_, name)| *name)
        .collect::<Vec<_>>()
        .join(",")
}

/// Texte venu du réseau (noms DNS, en-têtes HTTP, SNI…) : UTF-8 approché, caractères de
/// contrôle remplacés. Un ESC laissé tel quel serait exécuté par le terminal de la TUI.
pub fn text(bytes: &[u8]) -> String {
    clean(&String::from_utf8_lossy(bytes))
}

pub fn clean(s: &str) -> String {
    s.chars().map(|c| if c.is_control() { '·' } else { c }).collect()
}

/// Première ligne du payload si elle est lisible (bannière, commande texte).
pub fn printable_line(data: &[u8], limit: usize) -> Option<String> {
    let end = data.iter().position(|&b| b == b'\n').unwrap_or(data.len());
    let mut line = &data[..end.min(limit)];
    if line.last() == Some(&b'\r') {
        line = &line[..line.len() - 1];
    }
    if line.len() < 3 {
        return None;
    }
    let printable = line.iter().filter(|&&b| (32..127).contains(&b)).count();
    (printable * 10 >= line.len() * 9)
        .then(|| line.iter().map(|&b| if (32..127).contains(&b) { b as char } else { '·' }).collect())
}

/// Valeurs GREASE (RFC 8701) : 0x0a0a, 0x1a1a … 0xfafa.
pub fn is_grease(v: u16) -> bool {
    v & 0x0f0f == 0x0a0a && (v >> 8) == (v & 0xff)
}

pub fn join<T: ToString>(values: &[T], sep: &str) -> String {
    values.iter().map(ToString::to_string).collect::<Vec<_>>().join(sep)
}

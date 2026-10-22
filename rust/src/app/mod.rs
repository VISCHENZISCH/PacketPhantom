//! Couche applicative : détection par contenu d'abord, par port ensuite.

pub mod dhcp;
pub mod dns;
pub mod http;
pub mod tls;

use crate::fmt;
use crate::packet::Packet;
use crate::services;

const DNS_PORTS: [(u16, &str); 3] = [(53, "DNS"), (5353, "MDNS"), (5355, "LLMNR")];

fn dns_flavor(sport: u16, dport: u16) -> Option<&'static str> {
    DNS_PORTS
        .iter()
        .find(|(port, _)| *port == dport || *port == sport)
        .map(|(_, name)| *name)
}

fn ports(p: &Packet) -> (u16, u16) {
    (p.sport.unwrap_or(0), p.dport.unwrap_or(0))
}

pub fn tcp(p: &mut Packet) {
    let payload = p.payload_slice().to_vec();
    let (sport, dport) = ports(p);
    if tls::inspect(p, &payload) || http::inspect(p, &payload) {
        return;
    }
    if let Some(flavor) = dns_flavor(sport, dport) {
        // DNS sur TCP : préfixe de longueur sur 2 octets.
        if payload.len() > 2 && dns::inspect(p, &payload[2..], flavor) {
            return;
        }
    }
    let service = services::lookup(sport, dport);
    if let Some(name) = service {
        p.proto = name;
    }
    match fmt::printable_line(&payload, 90) {
        Some(line) => {
            if line.starts_with("SSH-") {
                p.proto = "SSH";
                p.banner = Some(line.clone());
            } else if (sport < 1024 && line.as_bytes()[..3].iter().all(u8::is_ascii_digit))
                || line.starts_with("+OK")
                || line.starts_with("* OK")
            {
                p.banner = Some(line.clone());
            }
            p.info = line;
        }
        None => {
            if let Some(name) = service {
                p.info = format!("{sport} → {dport} [{}] {name} ({} o)", fmt::tcp_flags(p.tcp_flags), payload.len());
            }
        }
    }
}

pub fn udp(p: &mut Packet) {
    let payload = p.payload_slice().to_vec();
    let (sport, dport) = ports(p);
    if let Some(flavor) = dns_flavor(sport, dport) {
        if dns::inspect(p, &payload, flavor) {
            return;
        }
    }
    if matches!(sport, 67 | 68) && matches!(dport, 67 | 68) && dhcp::inspect(p, &payload) {
        return;
    }
    if sport == 443 || dport == 443 {
        p.proto = "QUIC";
        p.info = quic_info(&payload);
        return;
    }
    if let Some(name) = services::lookup(sport, dport) {
        p.proto = name;
    }
    if let Some(line) = fmt::printable_line(&payload, 90) {
        p.info = line;
    }
}

fn quic_info(payload: &[u8]) -> String {
    let Some(&first) = payload.first() else { return "QUIC".into() };
    if first & 0x80 == 0 {
        return format!("QUIC 1-RTT (en-tête court, {} o)", payload.len());
    }
    let kind = match (first >> 4) & 0x03 {
        0 => "Initial",
        1 => "0-RTT",
        2 => "Handshake",
        _ => "Retry",
    };
    let version = payload.get(1..5).map_or(0, |v| u32::from_be_bytes([v[0], v[1], v[2], v[3]]));
    format!("QUIC {kind}  version=0x{version:08x}  ({} o)", payload.len())
}

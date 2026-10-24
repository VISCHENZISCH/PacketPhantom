//! DHCP (BOOTP + options) : type de message, nom d'hôte, adresse demandée.

use std::net::Ipv4Addr;

use crate::fmt;
use crate::packet::{App, Dhcp, Packet};

const MAGIC: [u8; 4] = [99, 130, 83, 99];

fn type_name(t: u8) -> &'static str {
    match t {
        1 => "Discover", 2 => "Offer", 3 => "Request", 4 => "Decline",
        5 => "ACK", 6 => "NAK", 7 => "Release", 8 => "Inform",
        _ => "?",
    }
}

pub fn inspect(p: &mut Packet, payload: &[u8]) -> bool {
    if payload.len() < 240 || payload[236..240] != MAGIC {
        return false;
    }
    let mut dhcp = Dhcp { client_mac: fmt::mac(&payload[28..34]), ..Default::default() };
    let mut opts = &payload[240..];
    while let Some(&code) = opts.first() {
        match code {
            0 => {
                opts = &opts[1..];
                continue;
            }
            255 => break,
            _ => {}
        }
        let Some(&len) = opts.get(1) else { break };
        let Some(value) = opts.get(2..2 + usize::from(len)) else { break };
        match (code, value) {
            (53, [t, ..]) => dhcp.msg_type = type_name(*t).into(),
            (12, name) => dhcp.hostname = fmt::text(name),
            (50, [a, b, c, d]) => dhcp.requested = Ipv4Addr::new(*a, *b, *c, *d).to_string(),
            _ => {}
        }
        opts = &opts[2 + usize::from(len)..];
    }
    p.proto = "DHCP";
    p.info = format!("DHCP {}", dhcp.msg_type);
    if !dhcp.hostname.is_empty() {
        p.info.push_str(&format!("  hôte={}", dhcp.hostname));
    }
    p.set_app(App::Dhcp(dhcp));
    true
}

//! DNS / mDNS / LLMNR : question, réponses, code retour (avec compression de noms).

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::packet::{App, Dns, Packet};
use crate::reader::{be16, Reader};

pub fn type_name(t: u16) -> String {
    match t {
        1 => "A", 2 => "NS", 5 => "CNAME", 6 => "SOA", 12 => "PTR", 15 => "MX", 16 => "TXT",
        28 => "AAAA", 33 => "SRV", 64 => "SVCB", 65 => "HTTPS", 255 => "ANY",
        other => return other.to_string(),
    }
    .into()
}

fn rcode_name(rcode: u8) -> String {
    match rcode {
        1 => "FORMERR", 2 => "SERVFAIL", 3 => "NXDOMAIN", 4 => "NOTIMP", 5 => "REFUSED",
        other => return other.to_string(),
    }
    .into()
}

/// Lit un nom DNS à `pos` (pointeurs de compression suivis, boucles bornées).
/// Retourne le nom et la position qui suit le nom dans le message.
fn read_name(msg: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut resume = None;
    for _ in 0..128 {
        let len = *msg.get(pos)? as usize;
        if len == 0 {
            return Some((labels.join("."), resume.unwrap_or(pos + 1)));
        }
        if len & 0xc0 == 0xc0 {
            let target = (usize::from(be16(msg, pos)?)) & 0x3fff;
            resume.get_or_insert(pos + 2);
            pos = target;
            continue;
        }
        let label = msg.get(pos + 1..pos + 1 + len)?;
        labels.push(String::from_utf8_lossy(label).into_owned());
        pos += 1 + len;
    }
    None
}

fn rdata(msg: &[u8], rtype: u16, start: usize, data: &[u8]) -> String {
    match (rtype, data.len()) {
        (1, 4) => Ipv4Addr::new(data[0], data[1], data[2], data[3]).to_string(),
        (28, 16) => Ipv6Addr::from(<[u8; 16]>::try_from(data).unwrap_or_default()).to_string(),
        (2 | 5 | 12, _) => read_name(msg, start).map(|(n, _)| n).unwrap_or_default(),
        (15, _) => read_name(msg, start + 2).map(|(n, _)| n).unwrap_or_default(),
        (16, _) => {
            let mut r = Reader::new(data);
            let mut parts = Vec::new();
            while let Some(mut s) = r.vec8() {
                parts.push(String::from_utf8_lossy(s.rest()).into_owned());
            }
            parts.join(" ")
        }
        (_, n) => format!("({n} octets)"),
    }
}

fn parse(msg: &[u8]) -> Option<Dns> {
    if msg.len() < 12 {
        return None;
    }
    let flags = be16(msg, 2)?;
    let (qdcount, ancount) = (be16(msg, 4)?, be16(msg, 6)?);
    if qdcount > 32 || ancount > 256 {
        return None;
    }
    let mut dns = Dns { qr: flags & 0x8000 != 0, rcode: (flags & 0x000f) as u8, ..Default::default() };
    let mut pos = 12;
    for i in 0..qdcount {
        let (name, next) = read_name(msg, pos)?;
        let qtype = be16(msg, next)?;
        if i == 0 {
            dns.qname = name;
            dns.qtype = type_name(qtype);
        }
        pos = next + 4;
    }
    for _ in 0..ancount {
        let Some((name, next)) = read_name(msg, pos) else { break };
        let (Some(rtype), Some(rdlen)) = (be16(msg, next), be16(msg, next + 8)) else { break };
        let start = next + 10;
        let Some(data) = msg.get(start..start + usize::from(rdlen)) else { break };
        dns.answers.push((name, type_name(rtype), rdata(msg, rtype, start, data)));
        pos = start + usize::from(rdlen);
    }
    Some(dns)
}

pub fn inspect(p: &mut Packet, payload: &[u8], flavor: &'static str) -> bool {
    let Some(dns) = parse(payload) else { return false };
    p.proto = flavor;
    p.domain = dns.qname.clone();
    p.info = if !dns.qr {
        format!("Requête {} {}", dns.qtype, dns.qname)
    } else if dns.rcode != 0 {
        format!("Réponse {} {}  {}", dns.qtype, dns.qname, rcode_name(dns.rcode))
    } else {
        let values: Vec<&str> = dns
            .answers
            .iter()
            .filter(|(_, t, _)| matches!(t.as_str(), "A" | "AAAA" | "CNAME"))
            .map(|(_, _, v)| v.as_str())
            .collect();
        let mut shown = values.iter().take(3).copied().collect::<Vec<_>>().join(", ");
        if values.len() > 3 {
            shown.push('…');
        }
        let arrow = if shown.is_empty() { String::new() } else { format!(" → {shown}") };
        format!("Réponse {} {}{arrow}", dns.qtype, dns.qname)
    };
    p.set_app(App::Dns(dns));
    true
}

//! Décodage couches 2 à 4 : lien → réseau → transport, puis délégation à `app`.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::app;
use crate::fmt;
use crate::packet::{App, Arp, Packet};
use crate::reader::{be16, Reader};

const ETH_IPV4: u16 = 0x0800;
const ETH_ARP: u16 = 0x0806;
const ETH_IPV6: u16 = 0x86dd;
const ETH_VLAN: [u16; 3] = [0x8100, 0x88a8, 0x9100];

/// Point d'entrée : décode une trame selon son type de lien (LINKTYPE_* de libpcap).
pub fn decode(data: &[u8], ts: f64, linktype: u32) -> Packet {
    let mut p = Packet::new(data, ts, linktype);
    match link(&mut p, data, linktype) {
        Some((ethertype, offset)) => network(&mut p, data, ethertype, offset),
        None if p.info.is_empty() => {
            p.proto = "?";
            p.info = format!("Type de lien {linktype} non pris en charge");
        }
        None => {}
    }
    p
}

// ------------------------------------------------------------------ couche 2

fn link(p: &mut Packet, data: &[u8], linktype: u32) -> Option<(u16, usize)> {
    match linktype {
        1 => ethernet(p, data),
        113 => Some((be16(data, 14)?, 16)),           // Linux cooked (SLL)
        276 => Some((be16(data, 0)?, 20)),            // Linux cooked v2 (SLL2)
        0 => null_loopback(data, false),              // BSD loopback (ordre hôte)
        108 => null_loopback(data, true),             // OpenBSD loopback
        101 | 12 | 14 => raw_ip(data),                // IP brut
        228 => Some((ETH_IPV4, 0)),
        229 => Some((ETH_IPV6, 0)),
        _ => None,
    }
}

fn ethernet(p: &mut Packet, data: &[u8]) -> Option<(u16, usize)> {
    if data.len() < 14 {
        p.proto = "ETH";
        p.mark_malformed("Ethernet");
        return None;
    }
    p.dmac = fmt::mac(&data[0..6]);
    p.smac = fmt::mac(&data[6..12]);
    let mut ethertype = be16(data, 12)?;
    let mut offset = 14;
    while ETH_VLAN.contains(&ethertype) {
        ethertype = be16(data, offset + 2)?;
        offset += 4;
    }
    if ethertype < 0x0600 {
        p.proto = "LLC";
        p.l4 = "LLC";
        p.info = format!("IEEE 802.3 / LLC ({ethertype} octets)");
        return None;
    }
    Some((ethertype, offset))
}

fn null_loopback(data: &[u8], big_endian: bool) -> Option<(u16, usize)> {
    let raw: [u8; 4] = data.get(0..4)?.try_into().ok()?;
    let family = if big_endian { u32::from_be_bytes(raw) } else { u32::from_le_bytes(raw) };
    match family {
        2 => Some((ETH_IPV4, 4)),
        24 | 28 | 30 => Some((ETH_IPV6, 4)),
        _ => None,
    }
}

fn raw_ip(data: &[u8]) -> Option<(u16, usize)> {
    match data.first()? >> 4 {
        4 => Some((ETH_IPV4, 0)),
        6 => Some((ETH_IPV6, 0)),
        _ => None,
    }
}

// ------------------------------------------------------------------ couche 3

fn network(p: &mut Packet, data: &[u8], ethertype: u16, offset: usize) {
    match ethertype {
        ETH_IPV4 => ipv4(p, data, offset),
        ETH_IPV6 => ipv6(p, data, offset),
        ETH_ARP => arp(p, data, offset),
        0x88cc => named(p, "LLDP", "Découverte de voisins LLDP".into()),
        0x888e => named(p, "EAPOL", "Authentification 802.1X".into()),
        other => named(p, "ETH", format!("EtherType 0x{other:04x}")),
    }
}

fn named(p: &mut Packet, proto: &'static str, info: String) {
    p.proto = proto;
    p.l4 = proto;
    p.info = info;
}

fn ipv4(p: &mut Packet, data: &[u8], offset: usize) {
    p.proto = "IPV4";
    p.ip_version = 4;
    let Some(h) = data.get(offset..).filter(|h| h.len() >= 20) else {
        return p.mark_malformed("IPv4");
    };
    let ihl = usize::from(h[0] & 0x0f) * 4;
    let total = usize::from(be16(h, 2).unwrap_or(0));
    if ihl < 20 || h.len() < ihl {
        return p.mark_malformed("IPv4");
    }
    p.ttl = Some(h[8]);
    p.src = Ipv4Addr::new(h[12], h[13], h[14], h[15]).to_string();
    p.dst = Ipv4Addr::new(h[16], h[17], h[18], h[19]).to_string();
    // TSO / captures locales : longueur totale parfois nulle → on prend la trame.
    let end = if total >= ihl { offset + total.min(h.len()) } else { data.len() };
    let fragment = be16(h, 6).unwrap_or(0) & 0x1fff;
    if fragment != 0 {
        p.l4 = "IPV4";
        p.info = format!("Fragment IP (offset {})", fragment * 8);
        return;
    }
    transport(p, data, h[9], offset + ihl, end);
}

fn ipv6(p: &mut Packet, data: &[u8], offset: usize) {
    p.proto = "IPV6";
    p.ip_version = 6;
    let Some(h) = data.get(offset..).filter(|h| h.len() >= 40) else {
        return p.mark_malformed("IPv6");
    };
    let payload_len = usize::from(be16(h, 4).unwrap_or(0));
    let src: [u8; 16] = h[8..24].try_into().unwrap_or_default();
    let dst: [u8; 16] = h[24..40].try_into().unwrap_or_default();
    p.ttl = Some(h[7]);
    p.src = Ipv6Addr::from(src).to_string();
    p.dst = Ipv6Addr::from(dst).to_string();
    let end = if payload_len > 0 { (offset + 40 + payload_len).min(data.len()) } else { data.len() };

    // En-têtes d'extension : hop-by-hop, routage, fragment, options destination, AH.
    let mut next = h[6];
    let mut pos = offset + 40;
    loop {
        match next {
            0 | 43 | 60 => {
                let (Some(&nh), Some(&len)) = (data.get(pos), data.get(pos + 1)) else {
                    return p.mark_malformed("IPv6");
                };
                next = nh;
                pos += (usize::from(len) + 1) * 8;
            }
            44 => {
                let Some(&nh) = data.get(pos) else { return p.mark_malformed("IPv6") };
                if be16(data, pos + 2).unwrap_or(0) >> 3 != 0 {
                    p.l4 = "IPV6";
                    p.info = "Fragment IPv6".into();
                    return;
                }
                next = nh;
                pos += 8;
            }
            51 => {
                let (Some(&nh), Some(&len)) = (data.get(pos), data.get(pos + 1)) else {
                    return p.mark_malformed("IPv6");
                };
                next = nh;
                pos += (usize::from(len) + 2) * 4;
            }
            _ => break,
        }
    }
    transport(p, data, next, pos, end);
}

fn arp(p: &mut Packet, data: &[u8], offset: usize) {
    p.proto = "ARP";
    p.l4 = "ARP";
    let mut r = Reader::new(data.get(offset..).unwrap_or_default());
    let parsed = (|| {
        let (_htype, _ptype, hlen, plen, op) = (r.u16()?, r.u16()?, r.u8()?, r.u8()?, r.u16()?);
        if hlen != 6 || plen != 4 {
            return None;
        }
        let ip = |b: &[u8]| Ipv4Addr::new(b[0], b[1], b[2], b[3]).to_string();
        let (sha, spa, tha, tpa) = (r.take(6)?, r.take(4)?, r.take(6)?, r.take(4)?);
        Some(Arp { op, hwsrc: fmt::mac(sha), psrc: ip(spa), hwdst: fmt::mac(tha), pdst: ip(tpa) })
    })();
    let Some(a) = parsed else { return p.mark_malformed("ARP") };
    p.info = if a.op == 1 {
        format!("Qui a {} ? Répondre à {}", a.pdst, a.psrc)
    } else {
        format!("{} est à {}", a.psrc, a.hwsrc)
    };
    p.src = a.psrc.clone();
    p.dst = a.pdst.clone();
    p.smac = a.hwsrc.clone();
    p.set_app(App::Arp(a));
}

// ------------------------------------------------------------------ couche 4

fn transport(p: &mut Packet, data: &[u8], proto: u8, start: usize, end: usize) {
    let end = end.max(start).min(data.len());
    let seg = data.get(start..end).unwrap_or_default();
    match proto {
        6 => tcp(p, seg, start),
        17 => udp(p, seg, start),
        1 => icmp(p, seg, start, false),
        58 => icmp(p, seg, start, true),
        2 => named(p, "IGMP", "Gestion de groupe multicast".into()),
        47 => named(p, "GRE", "Tunnel GRE".into()),
        50 => named(p, "ESP", "IPsec ESP".into()),
        89 => named(p, "OSPF", "Routage OSPF".into()),
        132 => named(p, "SCTP", "SCTP".into()),
        other => {
            let base = if p.ip_version == 6 { "IPV6" } else { "IPV4" };
            named(p, base, format!("Protocole IP {other}"));
        }
    }
}

fn tcp(p: &mut Packet, seg: &[u8], start: usize) {
    p.proto = "TCP";
    p.l4 = "TCP";
    if seg.len() < 20 {
        return p.mark_malformed("TCP");
    }
    let mut r = Reader::new(seg);
    let (sport, dport) = (r.u16().unwrap_or(0), r.u16().unwrap_or(0));
    let seq = r.u32().unwrap_or(0);
    let header_len = usize::from(seg[12] >> 4) * 4;
    let flags = seg[13];
    let window = be16(seg, 14).unwrap_or(0);
    if header_len < 20 || header_len > seg.len() {
        return p.mark_malformed("TCP");
    }
    p.sport = Some(sport);
    p.dport = Some(dport);
    p.seq = seq;
    p.tcp_flags = flags;
    p.window = window;
    if flags & fmt::SYN != 0 {
        tcp_options(p, &seg[20..header_len]);
    }
    p.set_payload(start + header_len, start + seg.len());
    p.info = format!("{sport} → {dport} [{}] Win={window} Len={}", fmt::tcp_flags(flags), p.payload_len);
    if p.payload_len > 0 {
        app::tcp(p);
    }
}

fn tcp_options(p: &mut Packet, mut opts: &[u8]) {
    while let Some(&kind) = opts.first() {
        let (name, len) = match kind {
            0 => ("EOL", 1),
            1 => ("NOP", 1),
            _ => {
                let Some(&len) = opts.get(1) else { break };
                let name = match kind {
                    2 => "MSS",
                    3 => "WScale",
                    4 => "SAckOK",
                    5 => "SAck",
                    8 => "Timestamp",
                    _ => "Other",
                };
                (name, usize::from(len).max(2))
            }
        };
        if kind == 2 {
            p.mss = be16(opts, 2);
        }
        p.tcp_options.push(name);
        if kind == 0 || len > opts.len() {
            break;
        }
        opts = &opts[len..];
    }
}

fn udp(p: &mut Packet, seg: &[u8], start: usize) {
    p.proto = "UDP";
    p.l4 = "UDP";
    if seg.len() < 8 {
        return p.mark_malformed("UDP");
    }
    let (sport, dport) = (be16(seg, 0).unwrap_or(0), be16(seg, 2).unwrap_or(0));
    let declared = usize::from(be16(seg, 4).unwrap_or(0));
    let end = if declared >= 8 { declared.min(seg.len()) } else { seg.len() };
    p.sport = Some(sport);
    p.dport = Some(dport);
    p.set_payload(start + 8, start + end);
    p.info = format!("{sport} → {dport} Len={}", p.payload_len);
    app::udp(p);
}

fn icmp(p: &mut Packet, seg: &[u8], start: usize, v6: bool) {
    p.proto = if v6 { "ICMPV6" } else { "ICMP" };
    p.l4 = p.proto;
    if seg.len() < 4 {
        return p.mark_malformed("ICMP");
    }
    let (kind, code) = (seg[0], seg[1]);
    p.set_payload(start + 8.min(seg.len()), start + seg.len());
    let name = if v6 { icmpv6_name(kind) } else { icmp_name(kind) };
    let echo = if v6 { matches!(kind, 128 | 129) } else { matches!(kind, 0 | 8) };
    p.info = if echo && seg.len() >= 8 {
        let (id, seq) = (be16(seg, 4).unwrap_or(0), be16(seg, 6).unwrap_or(0));
        format!("{name}  id=0x{id:04x} seq={seq}  ({} o)", p.payload_len)
    } else {
        format!("{name}  code={code}")
    };
}

fn icmp_name(kind: u8) -> String {
    match kind {
        0 => "Echo reply".into(),
        3 => "Destination injoignable".into(),
        5 => "Redirection".into(),
        8 => "Echo request".into(),
        11 => "TTL dépassé".into(),
        12 => "Problème de paramètre".into(),
        13 => "Timestamp".into(),
        other => format!("Type {other}"),
    }
}

fn icmpv6_name(kind: u8) -> String {
    match kind {
        1 => "Destination injoignable".into(),
        2 => "Paquet trop grand".into(),
        3 => "Délai dépassé".into(),
        128 => "Echo request".into(),
        129 => "Echo reply".into(),
        133 => "Sollicitation de routeur".into(),
        134 => "Annonce de routeur".into(),
        135 => "Sollicitation de voisin".into(),
        136 => "Annonce de voisin".into(),
        143 => "Rapport MLDv2".into(),
        other => format!("Type {other}"),
    }
}

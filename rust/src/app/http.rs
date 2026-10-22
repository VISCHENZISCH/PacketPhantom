//! HTTP/1.x : ligne de requête ou de statut, en-têtes, corps (tolère les en-têtes tronqués).

use crate::packet::{App, HttpRequest, HttpResponse, Packet};

const METHODS: [&[u8]; 9] = [
    b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"OPTIONS ", b"PATCH ", b"CONNECT ", b"TRACE ",
];

struct Head<'a> {
    first_line: String,
    headers: Vec<(String, String)>,
    body: &'a [u8],
}

fn split_head(payload: &[u8]) -> Head<'_> {
    let (head, body) = match payload.windows(4).position(|w| w == b"\r\n\r\n") {
        Some(i) => (&payload[..i], &payload[i + 4..]),
        None => (payload, &payload[payload.len()..]),
    };
    let text = String::from_utf8_lossy(head);
    let mut lines = text.split("\r\n");
    let first_line = lines.next().unwrap_or_default().to_string();
    let headers = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    Head { first_line, headers, body }
}

pub fn inspect(p: &mut Packet, payload: &[u8]) -> bool {
    if METHODS.iter().any(|m| payload.starts_with(m)) {
        request(p, split_head(payload));
        true
    } else if payload.starts_with(b"HTTP/1.") {
        response(p, split_head(payload));
        true
    } else {
        false
    }
}

fn request(p: &mut Packet, head: Head<'_>) {
    let mut parts = head.first_line.splitn(3, ' ');
    let method = parts.next().unwrap_or_default().to_string();
    let path = parts.next().unwrap_or("/").to_string();
    let version = parts.next().unwrap_or_default().to_string();
    let host = head.headers.iter().find(|(k, _)| k == "host").map(|(_, v)| v.clone()).unwrap_or_default();
    p.proto = "HTTP";
    p.domain = host.split(':').next().unwrap_or_default().to_string();
    p.info = if host.is_empty() { format!("{method} {path}") } else { format!("{method} {path}  ({host})") };
    p.set_app(App::HttpRequest(HttpRequest {
        method, path, version, host, headers: head.headers, body: head.body.to_vec(),
    }));
}

fn response(p: &mut Packet, head: Head<'_>) {
    let mut parts = head.first_line.splitn(3, ' ');
    let version = parts.next().unwrap_or_default().to_string();
    let code = parts.next().and_then(|c| c.parse().ok()).unwrap_or(0);
    let reason = parts.next().unwrap_or_default().to_string();
    let find = |name: &str| head.headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str());
    let mut info = format!("HTTP {code} {reason}").trim_end().to_string();
    if let Some(ct) = find("content-type") {
        info.push_str(&format!("  [{}]", ct.split(';').next().unwrap_or(ct)));
    }
    if let Some(server) = find("server") {
        info.push_str(&format!("  Server: {server}"));
    }
    p.proto = "HTTP";
    p.info = info;
    p.set_app(App::HttpResponse(HttpResponse { code, reason, version, headers: head.headers }));
}

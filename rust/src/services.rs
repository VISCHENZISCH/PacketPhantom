//! Services reconnus par port. Table unique, triée, utilisée pour la recherche et pour Python.

pub const SERVICES: &[(u16, &str)] = &[
    (20, "FTP-DATA"), (21, "FTP"), (22, "SSH"), (23, "TELNET"), (25, "SMTP"), (53, "DNS"),
    (67, "DHCP"), (68, "DHCP"), (69, "TFTP"), (80, "HTTP"), (88, "KERBEROS"), (110, "POP3"),
    (123, "NTP"), (135, "MSRPC"), (137, "NBNS"), (138, "NBDS"), (139, "NETBIOS"), (143, "IMAP"),
    (161, "SNMP"), (162, "SNMP"), (389, "LDAP"), (443, "HTTPS"), (445, "SMB"), (465, "SMTPS"),
    (514, "SYSLOG"), (587, "SMTP"), (636, "LDAPS"), (853, "DOT"), (993, "IMAPS"), (995, "POP3S"),
    (1194, "OPENVPN"), (1433, "MSSQL"), (1883, "MQTT"), (1900, "SSDP"), (3306, "MYSQL"),
    (3389, "RDP"), (5060, "SIP"), (5353, "MDNS"), (5355, "LLMNR"), (5432, "POSTGRES"),
    (5900, "VNC"), (6379, "REDIS"), (8080, "HTTP-ALT"), (8443, "HTTPS-ALT"), (9200, "ELASTIC"),
    (11211, "MEMCACHED"), (27017, "MONGODB"), (51820, "WIREGUARD"),
];

/// Protocoles produits par le décodeur en plus des services.
pub const PROTOCOLS: &[&str] = &[
    "ETH", "IP", "IPV4", "IPV6", "TCP", "UDP", "ICMP", "ICMPV6", "ARP", "IGMP", "GRE", "ESP",
    "OSPF", "SCTP", "TLS", "QUIC", "LLDP", "EAPOL",
];

pub fn by_port(port: u16) -> Option<&'static str> {
    SERVICES
        .binary_search_by_key(&port, |&(p, _)| p)
        .ok()
        .map(|i| SERVICES[i].1)
}

/// Nom de service : port destination prioritaire.
pub fn lookup(sport: u16, dport: u16) -> Option<&'static str> {
    by_port(dport).or_else(|| by_port(sport))
}

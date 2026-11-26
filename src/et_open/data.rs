//! Static Suricata 7.0.3 defaults and ET categories.

use crate::Model;

const SIGNATURE: &[&str] = &[
    "malware",
    "web_specific_apps",
    "exploit_kit",
    "phishing",
    "mobile_malware",
    "exploit",
    "web_server",
    "web_client",
    "scan",
    "user_agents",
    "ja3",
    "coinminer",
    "current_events",
    "attack_response",
    "dos",
    "worm",
    "scada",
    "activex",
    "dns",
];
const POLICY: &[&str] = &[
    "dyn_dns",
    "info",
    "hunting",
    "file_sharing",
    "ta_abused_services",
    "remote_access",
    "p2p",
    "games",
    "chat",
    "inappropriate",
    "adware_pup",
];

pub(super) fn model(path: &str) -> Option<Model> {
    let category = path.strip_prefix("emerging-")?.strip_suffix(".rules")?;
    if SIGNATURE.contains(&category) {
        Some(Model::EtSignature)
    } else if POLICY.contains(&category) {
        Some(Model::EtPolicySignature)
    } else {
        None
    }
}

// Values, not implementation code, from Suricata 7.0.3 suricata.yaml.in,
// vars.address-groups and vars.port-groups. HOME_NET remains caller-supplied.
pub(super) fn variable(name: &str, port: bool) -> Option<&'static str> {
    if port {
        Some(match name {
            "HTTP_PORTS" => "80",
            "SHELLCODE_PORTS" => "!80",
            "ORACLE_PORTS" => "1521",
            "SSH_PORTS" => "22",
            "DNP3_PORTS" => "20000",
            "MODBUS_PORTS" => "502",
            "FILE_DATA_PORTS" => "[$HTTP_PORTS,110,143]",
            "FTP_PORTS" => "21",
            "GENEVE_PORTS" => "6081",
            "VXLAN_PORTS" => "4789",
            "TEREDO_PORTS" => "3544",
            _ => return None,
        })
    } else {
        Some(match name {
            "EXTERNAL_NET" | "AIM_SERVERS" => "!$HOME_NET",
            "HTTP_SERVERS" | "SMTP_SERVERS" | "SQL_SERVERS" | "DNS_SERVERS" | "TELNET_SERVERS"
            | "DC_SERVERS" | "DNP3_SERVER" | "DNP3_CLIENT" | "MODBUS_CLIENT" | "MODBUS_SERVER"
            | "ENIP_CLIENT" | "ENIP_SERVER" => "$HOME_NET",
            _ => return None,
        })
    }
}

// Suricata 7.0.3 etc/reference.config. The first definition wins (secunia
// occurs twice), as in its configuration loader. Archive copies are ignored.
pub(super) fn reference(kind: &str) -> Option<&'static str> {
    Some(match kind {
        "bugtraq" | "bid" => "http://www.securityfocus.com/bid/",
        "cve" => "http://cve.mitre.org/cgi-bin/cvename.cgi?name=",
        "secunia" => "http://www.secunia.com/advisories/",
        "arachNIDS" => "http://www.whitehats.com/info/IDS",
        "McAfee" => "http://vil.nai.com/vil/content/v_",
        "nessus" => "http://cgi.nessus.org/plugins/dump.php3?id=",
        "url" | "telus" => "http://",
        "et" => "http://doc.emergingthreats.net/",
        "etpro" => "http://doc.emergingthreatspro.com/",
        "osvdb" => "http://osvdb.org/show/osvdb/",
        "threatexpert" | "md5" => "http://www.threatexpert.com/report.aspx?md5=",
        "exploitdb" => "http://www.exploit-db.com/exploits/",
        "openpacket" => "https://www.openpacket.org/capture/grab/",
        "securitytracker" => "http://securitytracker.com/id?",
        "xforce" => "http://xforce.iss.net/xforce/xfdb/",
        "msft" => "http://technet.microsoft.com/security/bulletin/",
        _ => return None,
    })
}

/// Canonicalizes supported and known unsupported legacy buffer spellings.
/// The bool distinguishes content modifiers from sticky buffers.
pub(super) fn buffer(name: &str) -> Option<(&str, bool)> {
    let legacy = match name {
        "http_method" => "http.method",
        "http_uri" => "http.uri",
        "http_raw_uri" => "http.uri.raw",
        "http_host" => "http.host",
        "http_raw_host" => "http.host.raw",
        "http_user_agent" => "http.user_agent",
        "http_referer" => return Some(("http.referer", false)),
        "http_cookie" => "http.cookie",
        "http_content_type" => return Some(("http.content_type", false)),
        "http_protocol" => return Some(("http.protocol", false)),
        "http_stat_code" => "http.stat_code",
        "http_stat_msg" => "http.stat_msg",
        "http_client_body" => "http.request_body",
        "http_server_body" => "http.response_body",
        "http_header" => "http.header",
        "http_raw_header" => "http.header.raw",
        "http_header_names" => return Some(("http.header_names", false)),
        "http_accept" => return Some(("http.accept", false)),
        "http_accept_enc" => return Some(("http.accept_enc", false)),
        "http_accept_lang" => return Some(("http.accept_lang", false)),
        "http_connection" => return Some(("http.connection", false)),
        "file_data" => return Some(("file.data", false)),
        "dns_query" => return Some(("dns.query", false)),
        "tls_sni" => return Some(("tls.sni", false)),
        "tls_cert_subject" => return Some(("tls.cert_subject", false)),
        "tls_cert_issuer" => return Some(("tls.cert_issuer", false)),
        "tls_cert_serial" => return Some(("tls.cert_serial", false)),
        "ja3_hash" => return Some(("ja3.hash", false)),
        "ja3s_hash" => return Some(("ja3s.hash", false)),
        "ssh_proto" => return Some(("ssh.proto", false)),
        "ssh_software" => return Some(("ssh.software", false)),
        "ssh_hassh" => return Some(("ssh.hassh", false)),
        "ssh_hassh_server" => return Some(("ssh.hassh.server", false)),
        _ if name.contains('.') => return Some((name, false)),
        _ => return None,
    };
    Some((legacy, true))
}

pub(super) fn pcre_buffer(flag: char) -> Option<&'static str> {
    Some(match flag {
        'U' => "http.uri",
        'I' => "http.uri.raw",
        'H' => "http.header",
        'D' => "http.header.raw",
        'C' => "http.cookie",
        'M' => "http.method",
        'P' => "http.request_body",
        'Q' => "http.response_body",
        'S' => "http.stat_code",
        'Y' => "http.stat_msg",
        'V' => "http.user_agent",
        'W' => "http.host",
        'Z' => "http.host.raw",
        _ => return None,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Direction {
    Request,
    Response,
    Both,
    None,
}

pub(super) struct Buffer {
    pub kind: &'static str,
    pub field: &'static str,
    pub direction: Direction,
    pub request_value_only: bool,
}

pub(super) fn lookup(name: &str, response: bool) -> Option<Buffer> {
    use Direction::{Both, Request, Response};
    let (kind, field, direction) = match name {
        "http.method" => ("http", "method", Request),
        "http.uri" => ("http", "uri.normalized", Request),
        "http.uri.raw" => ("http", "uri", Request),
        "http.host" => ("http", "host.normalized", Request),
        "http.host.raw" => ("http", "host", Request),
        "http.user_agent" => ("http", "user_agent", Request),
        "http.referer" => ("http", "referer", Request),
        "http.cookie" => ("http", "cookie", Request),
        "http.content_type" => ("http", "content_type", Request),
        "http.protocol" => ("http", "version", Request),
        "http.stat_code" => ("http", "status_code", Response),
        "http.stat_msg" => ("http", "status_msg", Response),
        "http.request_body" => ("http", "body.request", Request),
        "http.response_body" => ("http", "body.response", Response),
        "file.data" => (
            "http",
            if response {
                "body.response"
            } else {
                "body.request"
            },
            Both,
        ),
        "http.header_names" => ("http", "header_names.joined", Request),
        "http.accept" => ("http", "accept", Request),
        "http.accept_enc" => ("http", "accept_encoding", Request),
        "http.accept_lang" => ("http", "accept_language", Request),
        "http.connection" => ("http", "connection", Request),
        "http.header" => ("http", "header_block", Request),
        "dns.query" => ("dns", "query", Request),
        "tls.sni" => ("tls", "server_name", Request),
        "tls.cert_subject" => ("tls", "subject.joined", Response),
        "tls.cert_issuer" => ("tls", "issuer.joined", Response),
        "tls.cert_serial" => ("tls", "serial", Response),
        "ja3.hash" => ("tls", "ja3", Request),
        "ja3s.hash" => ("tls", "ja3s", Response),
        "ssh.proto" => (
            "ssh",
            if response {
                "server.proto"
            } else {
                "client.proto"
            },
            Both,
        ),
        "ssh.software" => (
            "ssh",
            if response {
                "server.software"
            } else {
                "client.software"
            },
            Both,
        ),
        "ssh.hassh" => ("ssh", "hassh", Request),
        "ssh.hassh.server" => ("ssh", "hassh_server", Response),
        _ => return None,
    };
    // Suricata 7.0.3 registers both directions in detect-http-header.c,
    // detect-http-header-names.c, detect-http-cookie.c and the generic
    // detect-http-headers-stub.h used by detect-http-content-type.c and
    // detect-http-connection.c; detect-http-protocol.c also has both directions.
    // Our HTTP records retain only request values of those buffers.
    let request_value_only = matches!(
        name,
        "http.header"
            | "http.header_names"
            | "http.cookie"
            | "http.content_type"
            | "http.connection"
            | "http.protocol"
    );
    Some(Buffer {
        kind,
        field,
        direction,
        request_value_only,
    })
}

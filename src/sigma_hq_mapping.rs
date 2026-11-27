//! The data-driven logsource and field mapping shipped with the converter.

use std::sync::LazyLock;

use giganto_client::RawEventKind;

use crate::{
    FieldStatus, catalog_fields, field_status,
    yaml::{self, Node},
};

const DATA: &str = include_str!("../data/sigma_hq_mapping.yaml");

pub(super) static MAPPINGS: LazyLock<Vec<Mapping>> = LazyLock::new(|| {
    // This is immutable crate data, checked in the mapping tests. A broken
    // build cannot safely convert rules with a guessed replacement table.
    load().unwrap_or_else(|error| panic!("invalid embedded SigmaHQ mapping: {error}"))
});

pub(super) fn get<'a>(node: &'a Node, key: &str) -> Option<&'a Node> {
    let Node::Map(entries) = node else {
        return None;
    };
    entries.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

pub(super) fn text(node: &Node) -> Option<&str> {
    if let Node::Str(s) = node {
        Some(s)
    } else {
        None
    }
}

pub(super) struct Mapping {
    pub(super) logsource: Node,
    pub(super) kind: RawEventKind,
    pub(super) kind_name: String,
    pub(super) os: Option<String>,
    fields: Vec<(String, String)>,
    unmapped: Vec<String>,
    other: Other,
    pub(super) add: Option<Node>,
    pub(super) keywords: Option<String>,
}

enum Other {
    None,
    SnakeCaseColumn,
    Prefix(String),
}

impl Mapping {
    pub(super) fn matches(&self, logsource: &Node) -> bool {
        ["product", "category", "service"]
            .iter()
            .all(|key| get(&self.logsource, key) == get(logsource, key))
    }

    pub(super) fn field(&self, name: &str) -> Option<String> {
        if self.unmapped.iter().any(|n| n == name) {
            return None;
        }
        if let Some((_, target)) = self.fields.iter().find(|(n, _)| n == name) {
            return Some(target.clone());
        }
        match &self.other {
            Other::None => None,
            Other::Prefix(prefix) => Some(format!("{prefix}{name}")),
            Other::SnakeCaseColumn => {
                let target = snake_case(name);
                // Exclusions also cover aliases that normalize to the same
                // column, so alternate capitalization cannot bypass the table.
                if self.unmapped.iter().any(|name| snake_case(name) == target) {
                    return None;
                }
                catalog_fields(self.kind)
                    .filter(|fields| fields.contains(&target.as_str()))
                    .map(|_| target)
            }
        }
    }
}

fn snake_case(name: &str) -> String {
    let mut previous = None;
    let mut target = String::new();
    for c in name.chars() {
        if c.is_ascii_uppercase()
            && previous.is_some_and(|p: char| p.is_ascii_lowercase() || p.is_ascii_digit())
        {
            target.push('_');
        }
        target.push(c.to_ascii_lowercase());
        previous = Some(c);
    }
    target
}

fn string(node: Option<&Node>, key: &str) -> Result<String, String> {
    node.and_then(text)
        .map(str::to_string)
        .ok_or_else(|| format!("missing string {key}"))
}

fn load() -> Result<Vec<Mapping>, String> {
    let Node::Seq(entries) = yaml::load(DATA)? else {
        return Err("expected a list".into());
    };
    let mut mappings = Vec::new();
    for entry in entries {
        let logsource = get(&entry, "logsource")
            .cloned()
            .ok_or("missing logsource")?;
        let Node::Map(keys) = &logsource else {
            return Err("logsource must be a map".into());
        };
        if keys.is_empty()
            || keys.iter().any(|(key, value)| {
                !["product", "category", "service"].contains(&key.as_str()) || text(value).is_none()
            })
        {
            return Err("invalid logsource triple".into());
        }
        let kind_name = string(get(&entry, "kind"), "kind")?;
        let kind = kind_name
            .parse::<RawEventKind>()
            .map_err(|e| e.to_string())?;
        if catalog_fields(kind).is_none() {
            return Err(format!("uncataloged kind {kind:?}"));
        }
        let mut fields = Vec::new();
        if let Some(Node::Map(names)) = get(&entry, "fields") {
            for (name, target) in names {
                let target = string(Some(target), name)?;
                if field_status(kind, &target) != FieldStatus::Known {
                    return Err(format!("{kind:?} has no {target}"));
                }
                fields.push((name.clone(), target));
            }
        }
        let unmapped = match get(&entry, "unmapped") {
            Some(Node::Seq(names)) => names
                .iter()
                .map(|n| string(Some(n), "unmapped"))
                .collect::<Result<_, _>>()?,
            None => Vec::new(),
            _ => return Err("unmapped must be a list".into()),
        };
        let other = match get(&entry, "other") {
            Some(Node::Str(s)) if s == "none" => Other::None,
            Some(Node::Str(s)) if s == "snake_case_column" => Other::SnakeCaseColumn,
            Some(node @ Node::Map(_)) => Other::Prefix(string(get(node, "prefix"), "prefix")?),
            _ => return Err("invalid other mapping".into()),
        };
        let add = get(&entry, "add").cloned();
        if let Some(node) = &add {
            let Node::Map(conditions) = node else {
                return Err("add must be a map".into());
            };
            for (key, _) in conditions {
                if field_status(kind, key.split('|').next().unwrap_or_default())
                    != FieldStatus::Known
                {
                    return Err(format!("invalid added field {key}"));
                }
            }
            crate::detection::parse(&Node::Map(vec![
                ("selection".into(), node.clone()),
                ("condition".into(), Node::Str("selection".into())),
            ]))
            .map_err(|e| e.to_string())?;
        }
        let keywords = get(&entry, "keywords")
            .map(|n| string(Some(n), "keywords"))
            .transpose()?;
        if keywords
            .as_ref()
            .is_some_and(|name| field_status(kind, name) != FieldStatus::Known)
        {
            return Err("invalid keyword field".into());
        }
        mappings.push(Mapping {
            logsource,
            kind,
            kind_name,
            os: get(&entry, "os")
                .map(|n| string(Some(n), "os"))
                .transpose()?,
            fields,
            unmapped,
            other,
            add,
            keywords,
        });
    }
    Ok(mappings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_loads_and_has_unique_logsource_triples() {
        let mappings = load().unwrap();
        assert_eq!(mappings.len(), 64);
        for (i, mapping) in mappings.iter().enumerate() {
            assert!(
                !mappings
                    .iter()
                    .skip(i + 1)
                    .any(|other| other.matches(&mapping.logsource))
            );
            if let Other::Prefix(prefix) = &mapping.other {
                assert!(crate::catalog_field_prefixes(mapping.kind).contains(&prefix.as_str()));
            }
        }
    }

    #[test]
    fn snake_case_exclusions_come_from_the_table_and_cover_aliases() {
        for mapping in MAPPINGS
            .iter()
            .filter(|m| matches!(m.other, Other::SnakeCaseColumn))
        {
            for name in ["AgentName", "AgentId", "LogonIdFull"] {
                assert!(mapping.unmapped.iter().any(|excluded| excluded == name));
                assert_eq!(mapping.field(name), None);
                assert_eq!(mapping.field(&snake_case(name)), None);
            }
            for name in ["AgentID", "Agent_Name", "Logon_IdFull", "logon_id"] {
                assert_eq!(mapping.field(name), None);
            }
        }
        // The generic snake-case rule itself does not exclude these columns.
        let mut mappings = load().unwrap();
        let mapping = mappings
            .iter_mut()
            .find(|m| m.kind_name == "process_create")
            .unwrap();
        mapping.unmapped.clear();
        assert_eq!(mapping.field("AgentName").as_deref(), Some("agent_name"));
    }
}

#[cfg(test)]
mod contract_tests {
    use std::collections::BTreeSet;

    use super::*;

    fn entry(
        product: Option<&str>,
        category: Option<&str>,
        service: Option<&str>,
        kind: &str,
    ) -> &'static Mapping {
        let keys = [
            ("product", product),
            ("category", category),
            ("service", service),
        ]
        .into_iter()
        .filter_map(|(k, v)| v.map(|v| (k.to_string(), Node::Str(v.to_string()))))
        .collect();
        let source = Node::Map(keys);
        let mapping = MAPPINGS
            .iter()
            .find(|m| m.matches(&source))
            .unwrap_or_else(|| panic!("missing {source:?}"));
        assert_eq!(mapping.kind_name, kind);
        assert_eq!(
            mapping.os.as_deref(),
            product.filter(|p| matches!(*p, "windows" | "linux"))
        );
        mapping
    }

    fn fields(mapping: &Mapping, expected: &[(&str, &str)]) {
        let actual: BTreeSet<_> = mapping
            .fields
            .iter()
            .map(|(a, b)| (a.as_str(), b.as_str()))
            .collect();
        assert_eq!(actual, expected.iter().copied().collect());
        for (source, target) in expected {
            assert_eq!(mapping.field(source).as_deref(), Some(*target));
        }
    }

    fn add(mapping: &Mapping, expected: Option<&str>) {
        assert_eq!(mapping.add, expected.map(|s| yaml::load(s).unwrap()));
    }

    #[test]
    fn network_mappings_cover_exact_fields_and_aliases() {
        let addresses = [
            ("src_ip", "orig_addr"),
            ("c-ip", "orig_addr"),
            ("dst_ip", "resp_addr"),
            ("s-ip", "resp_addr"),
            ("src_port", "orig_port"),
            ("dst_port", "resp_port"),
            ("s-port", "resp_port"),
        ];
        let zeek = [
            ("id.orig_h", "orig_addr"),
            ("id.resp_h", "resp_addr"),
            ("id.orig_p", "orig_port"),
            ("id.resp_p", "resp_port"),
        ];
        for category in ["proxy", "webserver"] {
            let mapping = entry(None, Some(category), None, "http");
            let mut expected = addresses.to_vec();
            expected.extend([
                ("c-uri", "uri"),
                ("cs-uri", "uri"),
                ("cs-host", "host"),
                ("c-useragent", "user_agent"),
                ("cs-user-agent", "user_agent"),
                ("cs-method", "method"),
                ("cs-referrer", "referer"),
                ("cs-referer", "referer"),
                ("cs-cookie", "cookie"),
                ("sc-status", "status_code"),
            ]);
            fields(mapping, &expected);
            add(mapping, None);
        }
        for (service, kind, same, renamed) in [
            (
                "http",
                "http",
                vec![
                    "method",
                    "host",
                    "uri",
                    "user_agent",
                    "status_code",
                    "status_msg",
                    "username",
                    "password",
                ],
                Some(("referrer", "referer")),
            ),
            (
                "dns",
                "dns",
                vec!["query", "qtype", "qclass", "rcode", "trans_id"],
                Some(("answers", "answer")),
            ),
            ("ssl", "tls", vec!["server_name"], None),
            (
                "conn",
                "conn",
                vec![
                    "service",
                    "conn_state",
                    "orig_bytes",
                    "resp_bytes",
                    "orig_pkts",
                    "resp_pkts",
                ],
                None,
            ),
        ] {
            let mapping = entry(Some("zeek"), None, Some(service), kind);
            let mut expected = zeek.to_vec();
            expected.extend(same.iter().map(|s| (*s, *s)));
            expected.extend(renamed);
            fields(mapping, &expected);
            add(mapping, None);
        }
        let mapping = entry(None, Some("dns"), None, "dns");
        let mut expected = addresses.to_vec();
        expected.extend([("query", "query"), ("answer", "answer")]);
        fields(mapping, &expected);
        fields(entry(None, Some("firewall"), None, "conn"), &addresses);
    }

    #[test]
    fn sysmon_triples_snake_case_exceptions_and_unsupported_log_sources() {
        let expected = [
            ("process_creation", "process_create"),
            ("file_change", "file_create_time"),
            ("network_connection", "network_connect"),
            ("process_termination", "process_terminate"),
            ("driver_load", "driver_load"),
            ("image_load", "image_load"),
            ("create_remote_thread", "create_remote_thread"),
            ("raw_access_thread", "raw_access_read"),
            ("process_access", "process_access"),
            ("file_event", "file_create"),
            ("registry_add", "registry_object_add_del"),
            ("registry_delete", "registry_object_add_del"),
            ("registry_set", "registry_value_set"),
            ("registry_rename", "registry_key_rename"),
            ("create_stream_hash", "file_create_stream_hash"),
            ("pipe_created", "pipe_event"),
            ("dns_query", "dns_query"),
            ("file_delete", "file_delete"),
            ("file_delete_detected", "file_delete_detected"),
            ("process_tampering", "process_tamper"),
        ];
        for (category, kind) in expected {
            let mapping = entry(Some("windows"), Some(category), None, kind);
            assert!(matches!(mapping.other, Other::SnakeCaseColumn));
            for name in [
                "LogonId",
                "GrantedAccess",
                "CreationUtcTime",
                "PreviousCreationUtcTime",
                "AgentName",
                "AgentId",
                "LogonIdFull",
            ] {
                assert_eq!(mapping.field(name), None);
            }
            for name in ["RulecUnknownField", "Endpoint"] {
                assert_eq!(mapping.field(name), None);
            }
            if catalog_fields(mapping.kind).unwrap().contains(&"image") {
                assert_eq!(mapping.field("Image").as_deref(), Some("image"));
            }
            if catalog_fields(mapping.kind)
                .unwrap()
                .contains(&"target_filename")
            {
                assert_eq!(
                    mapping.field("TargetFilename").as_deref(),
                    Some("target_filename")
                );
            }
            add(
                mapping,
                match category {
                    "registry_add" => Some("event_type: CreateKey"),
                    "registry_delete" => Some("event_type: [DeleteKey, DeleteValue]"),
                    _ => None,
                },
            );
        }
        for (category, kind) in expected.into_iter().filter(|(c, _)| {
            [
                "process_creation",
                "process_termination",
                "network_connection",
                "file_event",
                "file_delete",
                "raw_access_thread",
            ]
            .contains(c)
        }) {
            let mapping = entry(Some("linux"), Some(category), None, kind);
            assert!(matches!(mapping.other, Other::SnakeCaseColumn));
            add(mapping, None);
        }
        assert_eq!(
            entry(
                Some("windows"),
                Some("process_tampering"),
                None,
                "process_tamper"
            )
            .field("Type")
            .as_deref(),
            Some("tamper_type")
        );
        assert_eq!(
            entry(
                Some("windows"),
                Some("process_creation"),
                None,
                "process_create"
            )
            .field("CommandLine")
            .as_deref(),
            Some("command_line")
        );
        assert_eq!(
            entry(
                Some("windows"),
                Some("network_connection"),
                None,
                "network_connect"
            )
            .field("SourceIp")
            .as_deref(),
            Some("source_ip")
        );
        for logsource in [
            "product: windows\ncategory: registry_event",
            "product: windows\ncategory: wmi_event",
            "product: windows\ncategory: clipboard_capture",
            "product: windows\ncategory: sysmon_status",
            "product: windows\ncategory: sysmon_error",
            "product: windows\ncategory: file_executable_detected",
            "product: linux\ncategory: image_load",
            "product: windows\ncategory: process_creation\nservice: sysmon",
        ] {
            let node = yaml::load(logsource).unwrap();
            assert!(!MAPPINGS.iter().any(|m| m.matches(&node)), "{logsource}");
        }
        // definition and other descriptive keys do not participate in matching.
        let node = yaml::load("product: windows\ncategory: process_creation\ndefinition: ignored")
            .unwrap();
        assert!(MAPPINGS.iter().any(|m| m.matches(&node)));
    }

    #[test]
    fn windows_event_log_channels_categories_and_dynamic_fields() {
        let services = [
            ("security", "Security"),
            ("system", "System"),
            ("application", "Application"),
            ("powershell", "Microsoft-Windows-PowerShell/Operational"),
            ("powershell-classic", "Windows PowerShell"),
            (
                "windefend",
                "Microsoft-Windows-Windows Defender/Operational",
            ),
            (
                "taskscheduler",
                "Microsoft-Windows-TaskScheduler/Operational",
            ),
            ("wmi", "Microsoft-Windows-WMI-Activity/Operational"),
            ("dns-server", "DNS Server"),
            (
                "driver-framework",
                "Microsoft-Windows-DriverFrameworks-UserMode/Operational",
            ),
            ("bits-client", "Microsoft-Windows-Bits-Client/Operational"),
            (
                "codeintegrity-operational",
                "Microsoft-Windows-CodeIntegrity/Operational",
            ),
            (
                "firewall-as",
                "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
            ),
            ("ntlm", "Microsoft-Windows-NTLM/Operational"),
            (
                "terminalservices-localsessionmanager",
                "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
            ),
            ("sysmon", "Microsoft-Windows-Sysmon/Operational"),
        ];
        let expected = [
            ("EventID", "event_id"),
            ("Channel", "channel"),
            ("Provider_Name", "provider"),
            ("Computer", "computer"),
            ("Level", "level"),
            ("Task", "task"),
            ("Opcode", "opcode"),
            ("Version", "version"),
            ("EventRecordID", "record_id"),
        ];
        for (service, channel) in services {
            let mapping = entry(
                Some("windows"),
                None,
                Some(service),
                "endpoint_windows_event_log",
            );
            add(mapping, Some(&format!("channel: '{channel}'")));
            fields(mapping, &expected);
            assert_eq!(mapping.field("Keywords"), None);
            assert_eq!(
                mapping.field("CommandLine").as_deref(),
                Some("event_data.CommandLine")
            );
        }
        for (category, event_id) in [
            ("ps_module", 4103),
            ("ps_script", 4104),
            ("ps_classic_start", 400),
            ("ps_classic_provider_start", 600),
            ("ps_classic_script", 800),
        ] {
            let mapping = entry(
                Some("windows"),
                Some(category),
                None,
                "endpoint_windows_event_log",
            );
            let channels = if category.starts_with("ps_classic_") {
                "'Windows PowerShell'"
            } else {
                "['Microsoft-Windows-PowerShell/Operational', 'PowerShellCore/Operational']"
            };
            add(
                mapping,
                Some(&format!("channel: {channels}\nevent_id: {event_id}")),
            );
            fields(mapping, &expected);
            assert_eq!(
                mapping.field("Data").as_deref(),
                if category.starts_with("ps_classic_") {
                    None
                } else {
                    Some("event_data.Data")
                }
            );
            assert_eq!(mapping.field("Keywords"), None);
        }
    }

    #[test]
    fn journald_and_auditd_have_only_the_specified_mappings() {
        for (service, condition) in [
            (None, None),
            (Some("syslog"), None),
            (Some("auth"), Some("fields.SYSLOG_FACILITY: ['4', '10']")),
            (Some("cron"), Some("fields.SYSLOG_FACILITY: '9'")),
            (Some("sshd"), Some("fields.SYSLOG_IDENTIFIER: sshd")),
            (Some("sudo"), Some("fields.SYSLOG_IDENTIFIER: sudo")),
            (Some("vsftpd"), Some("fields.SYSLOG_IDENTIFIER: vsftpd")),
            (
                Some("clamav"),
                Some("fields.SYSLOG_IDENTIFIER: [clamd, freshclam]"),
            ),
        ] {
            let mapping = entry(Some("linux"), None, service, "endpoint_journald");
            assert_eq!(mapping.keywords.as_deref(), Some("fields.MESSAGE"));
            assert!(matches!(mapping.other, Other::None));
            assert!(mapping.fields.is_empty());
            assert_eq!(mapping.field("MESSAGE"), None);
            add(mapping, condition);
        }
        let mapping = entry(Some("linux"), None, Some("auditd"), "endpoint_auditd");
        fields(mapping, &[("type", "record_type")]);
        assert_eq!(mapping.field("a0").as_deref(), Some("fields.a0"));
        assert!(mapping.keywords.is_none());
        add(mapping, None);
        assert_eq!(MAPPINGS.len(), 8 + 20 + 6 + 21 + 8 + 1);
    }
}

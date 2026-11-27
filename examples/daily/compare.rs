use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

use rulec::{Cidr, RuleBundle, compile, inspect_et_open_rule};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{Result, read, records, sources::Report, write};

pub(super) const SCOPES: [&str; 5] = [
    "http_request",
    "http_response",
    "tls_certificate_response",
    "ssh_server_banner",
    "dns",
];
pub(super) const HOME_NET: [&str; 3] = ["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"];

#[derive(Serialize, Deserialize)]
pub(super) struct RuleInfo {
    pub sid: String,
    pub rev: Option<u64>,
    pub msg: String,
    pub kind: String,
    pub fields: Vec<String>,
    pub partial_header: bool,
    pub threshold: bool,
    pub scopes: Vec<String>,
}

// Inspect option names without mistaking quoted message/content for syntax.
fn options(line: &[u8]) -> Option<Vec<(&str, &str)>> {
    let text = std::str::from_utf8(line).ok()?;
    let (_, options) = text.split_once('(')?;
    let mut quoted = false;
    let mut escaped = false;
    let mut start = 0;
    let mut result = Vec::new();
    for (i, ch) in options.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' => escaped = true,
            '"' => quoted = !quoted,
            ';' if !quoted => {
                let option = options.get(start..i)?.trim();
                result.push(
                    option
                        .split_once(':')
                        .map_or((option, ""), |(k, v)| (k.trim(), v.trim())),
                );
                start = i + 1;
            }
            _ => {}
        }
    }
    Some(result)
}

fn sid(line: &[u8]) -> Option<String> {
    options(line)?
        .iter()
        .find(|(key, _)| *key == "sid")?
        .1
        .parse::<u64>()
        .ok()
        .map(|n| n.to_string())
}

// Source scopes are needed even for rules that conversion rejects. Rejection
// reasons come only from the actual conversion summary of this same archive.
fn source_scopes(line: &[u8]) -> BTreeSet<String> {
    let options = options(line).unwrap_or_default();
    let request_only = options.iter().any(|(key, value)| {
        *key == "flow"
            && value
                .split(',')
                .any(|v| matches!(v.trim(), "to_server" | "from_client"))
    });
    let response_only = options.iter().any(|(key, value)| {
        *key == "flow"
            && value
                .split(',')
                .any(|v| matches!(v.trim(), "to_client" | "from_server"))
    });
    let mut scopes = BTreeSet::new();
    for (key, value) in options {
        let scope = match key {
            "ssh.software" | "ssh_software" if !request_only => Some("ssh_server_banner"),
            "tls.cert_subject" | "tls_cert_subject" | "tls.cert_issuer" | "tls_cert_issuer" => {
                Some("tls_certificate_response")
            }
            "dns.query" | "dns_query" => Some("dns"),
            "http.stat_code" | "http_stat_code" | "http.stat_msg" | "http_stat_msg"
            | "http.response_body" | "http_server_body" => Some("http_response"),
            "file.data" | "file_data" => Some(if request_only {
                "http_request"
            } else {
                "http_response"
            }),
            "pcre" => {
                let flags = value
                    .trim_matches('"')
                    .rsplit_once('/')
                    .map_or("", |(_, flags)| flags);
                if flags.contains(['Q', 'S', 'Y']) {
                    scopes.insert("http_response".into());
                }
                if flags.contains(['U', 'I', 'H', 'D', 'C', 'M', 'P', 'V', 'W', 'Z']) {
                    scopes.insert("http_request".into());
                }
                None
            }
            name if name.starts_with("http.") || name.starts_with("http_") => {
                Some(if response_only {
                    "http_response"
                } else {
                    "http_request"
                })
            }
            _ => None,
        };
        if let Some(scope) = scope {
            scopes.insert(scope.into());
        }
    }
    scopes
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct RejectedRule {
    sid: String,
    reason: String,
}

fn rejected_scopes(
    lines: &[Vec<u8>],
    dropped: &BTreeMap<String, Vec<String>>,
) -> BTreeMap<String, Vec<RejectedRule>> {
    let reasons: BTreeMap<_, _> = dropped
        .iter()
        .flat_map(|(reason, ids)| ids.iter().map(move |id| (id, reason)))
        .collect();
    let mut result: BTreeMap<String, Vec<RejectedRule>> = BTreeMap::new();
    for line in lines {
        if let Some(id) = sid(line)
            && let Some(reason) = reasons.get(&id)
        {
            for scope in source_scopes(line) {
                let entry = RejectedRule {
                    sid: id.clone(),
                    reason: (*reason).clone(),
                };
                let list = result.entry(scope).or_default();
                if !list.contains(&entry) {
                    list.push(entry);
                }
            }
        }
    }
    result
}

impl RuleInfo {
    fn from_rules(rules: &[rulec::Rule], lines: &[Vec<u8>]) -> Result<Vec<Self>> {
        let originals: BTreeMap<_, _> = lines
            .iter()
            .filter_map(|line| sid(line).map(|id| (id, line)))
            .collect();
        rules
            .iter()
            .map(|rule| {
                let line = originals
                    .get(rule.source_rule_id())
                    .ok_or("accepted ET sid missing from source archive")?;
                let diagnostic = inspect_et_open_rule(line, rule.model())?;
                let kind = format!("{:?}", rule.kind());
                let fields = rule.fields().to_vec();
                let has =
                    |names: &[&str]| fields.iter().any(|field| names.contains(&field.as_str()));
                let mut scopes = Vec::new();
                if kind == "Http" {
                    let response =
                        has(&["status_code", "status_msg", "body.response", "response_len"]);
                    // file.data injects method=GET; that is not a request buffer.
                    if (has(&["method"]) && !response)
                        || has(&[
                            "uri",
                            "uri.normalized",
                            "host",
                            "host.normalized",
                            "header_block",
                            "user_agent",
                            "body.request",
                            "header_names.joined",
                            "cookie",
                            "referer",
                            "content_type",
                            "version",
                            "accept",
                            "accept_encoding",
                            "accept_language",
                            "connection",
                        ])
                    {
                        scopes.push("http_request".into());
                    }
                    if response {
                        scopes.push("http_response".into());
                    }
                }
                if kind == "Tls" && has(&["subject.joined", "issuer.joined"]) {
                    scopes.push("tls_certificate_response".into());
                }
                if kind == "Ssh" && has(&["server.software"]) {
                    scopes.push("ssh_server_banner".into());
                }
                if kind == "Dns" {
                    scopes.push("dns".into());
                }
                Ok(Self {
                    sid: rule.source_rule_id().into(),
                    rev: rule.source_rule_rev(),
                    msg: rule.title().into(),
                    kind,
                    fields,
                    partial_header: diagnostic.header_values_partly_missing,
                    threshold: diagnostic.ignores_threshold,
                    scopes,
                })
            })
            .collect()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub(super) struct Key {
    pub pcap: String,
    pub flow: u64,
    pub sid: String,
}

#[derive(Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Direction {
    ToServer,
    ToClient,
    #[default]
    Unknown,
}

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct Evidence {
    pub tuple: Value,
    #[serde(default)]
    pub direction: Direction,
    pub kind: String,
    pub fields: Vec<String>,
    pub missing: BTreeSet<String>,
}

#[derive(Serialize, Deserialize)]
pub(super) struct Pair {
    pub key: Key,
    pub classification: String,
    pub input_limit: bool,
    pub threshold: bool,
    pub evidence: Vec<Evidence>,
}

#[derive(Serialize, Deserialize)]
pub(super) struct RuleResult {
    pub sid: String,
    pub rev: Option<u64>,
    pub msg: String,
    pub classification: String,
    pub input_limit: bool,
    pub threshold: bool,
    pub pairs: Vec<Pair>,
}

#[derive(Serialize, Deserialize)]
pub(super) struct Differential {
    pub status: String,
    pub reason: Option<String>,
    pub errors: Vec<String>,
    pub suricata_version: String,
    pub et_archive_sha256: String,
    pub home_net: Vec<String>,
    pub rules: Vec<RuleResult>,
    pub counts: BTreeMap<String, usize>,
    pub coverage: BTreeMap<String, Vec<Value>>,
    pub missing_scopes: Vec<String>,
    pub no_comparable_rules: BTreeMap<String, Vec<RejectedRule>>,
    pub dropped_alerts: BTreeMap<String, Value>,
    pub pcap_alert_counts: BTreeMap<String, usize>,
    pub excluded_pcaps: Vec<Value>,
}

type Hits = BTreeMap<Key, Vec<Evidence>>;

pub(super) fn classify(
    infos: &[RuleInfo],
    suricata: &Hits,
    matched: &Hits,
    available: &BTreeMap<(String, u64, String), Vec<Evidence>>,
    dropped: &BTreeMap<String, Vec<String>>,
    rejected: &BTreeMap<String, Vec<RejectedRule>>,
) -> Differential {
    let mut result = Differential {
        status: "completed".into(),
        reason: None,
        errors: Vec::new(),
        suricata_version: String::new(),
        et_archive_sha256: String::new(),
        home_net: HOME_NET.map(str::to_owned).to_vec(),
        rules: Vec::new(),
        counts: BTreeMap::from([
            ("equal".into(), 0),
            ("suricata_only".into(), 0),
            ("rulec_only".into(), 0),
            ("both".into(), 0),
        ]),
        coverage: SCOPES.map(|s| (s.to_string(), Vec::new())).into(),
        missing_scopes: Vec::new(),
        no_comparable_rules: BTreeMap::new(),
        dropped_alerts: BTreeMap::new(),
        pcap_alert_counts: BTreeMap::new(),
        excluded_pcaps: Vec::new(),
    };
    let all_keys: BTreeSet<_> = suricata.keys().chain(matched.keys()).collect();
    for rule in infos {
        let mut pairs = Vec::new();
        let mut sides = BTreeSet::new();
        for key in all_keys.iter().copied().filter(|key| key.sid == rule.sid) {
            let s = suricata.contains_key(key);
            let r = matched.contains_key(key);
            let classification = match (s, r) {
                (true, true) => "equal",
                (true, false) => "suricata_only",
                _ => "rulec_only",
            };
            if s {
                for scope in &rule.scopes {
                    // Direction-specific buffers already identify the side. A
                    // neutral SSH rule has both alternatives, so a client-only
                    // alert cannot prove server-banner coverage.
                    let neutral_ssh = scope == "ssh_server_banner"
                        && rule.fields.iter().any(|field| field.starts_with("client"));
                    if neutral_ssh
                        && !suricata.get(key).is_some_and(|events| {
                            events
                                .iter()
                                .any(|event| event.direction == Direction::ToClient)
                        })
                    {
                        continue;
                    }
                    if let Some(list) = result.coverage.get_mut(scope)
                        && !list.iter().any(|v| v["sid"] == rule.sid)
                    {
                        list.push(json!({"sid": rule.sid}));
                    }
                }
            }
            if classification == "equal" {
                continue;
            }
            sides.insert(classification);
            let evidence = if r {
                matched.get(key).cloned().unwrap_or_default()
            } else {
                available
                    .get(&(key.pcap.clone(), key.flow, rule.kind.clone()))
                    .cloned()
                    .unwrap_or_else(|| {
                        let mut fallback = suricata.get(key).cloned().unwrap_or_default();
                        for evidence in &mut fallback {
                            evidence.kind.clone_from(&rule.kind);
                            evidence.missing.extend(rule.fields.iter().cloned());
                        }
                        fallback
                    })
            };
            let input_limit = s
                && !r
                && (rule.partial_header
                    || evidence
                        .iter()
                        .all(|e| rule.fields.iter().any(|f| e.missing.contains(f))));
            pairs.push(Pair {
                key: key.clone(),
                classification: classification.into(),
                input_limit,
                threshold: r && !s && rule.threshold,
                evidence,
            });
        }
        let classification = if sides.len() > 1 {
            "both"
        } else {
            sides.first().copied().unwrap_or("equal")
        };
        // A rule is suppressed if any mismatch carries a mark, as specified.
        let input_limit = pairs.iter().any(|p| p.input_limit);
        let threshold = pairs.iter().any(|p| p.threshold);
        *result.counts.entry(classification.into()).or_default() += 1;
        for list in result.coverage.values_mut() {
            for entry in list.iter_mut().filter(|entry| entry["sid"] == rule.sid) {
                entry["classification"] = json!(classification);
            }
        }
        result.rules.push(RuleResult {
            sid: rule.sid.clone(),
            rev: rule.rev,
            msg: rule.msg.clone(),
            classification: classification.into(),
            input_limit,
            threshold,
            pairs,
        });
    }
    for (reason, ids) in dropped {
        let hits: Vec<_> = suricata
            .keys()
            .filter(|key| ids.contains(&key.sid))
            .collect();
        let sids: BTreeSet<_> = hits.iter().map(|k| &k.sid).collect();
        result
            .dropped_alerts
            .insert(reason.clone(), json!({"count":hits.iter().map(|key| suricata.get(*key).map_or(0, Vec::len)).sum::<usize>(), "sids":sids}));
    }
    for (scope, compared) in &result.coverage {
        if !compared.is_empty() {
            continue;
        }
        let accepted = infos.iter().any(|rule| rule.scopes.contains(scope));
        if !accepted && let Some(rules) = rejected.get(scope).filter(|rules| !rules.is_empty()) {
            result.no_comparable_rules.insert(
                scope.clone(),
                rules
                    .iter()
                    .map(|rule| RejectedRule {
                        sid: rule.sid.clone(),
                        reason: rule.reason.clone(),
                    })
                    .collect(),
            );
        } else {
            result.missing_scopes.push(scope.clone());
        }
    }
    if !result.missing_scopes.is_empty() {
        result.errors.push(format!(
            "no compared rules in scopes: {}",
            result.missing_scopes.join(", ")
        ));
    }
    result
}

#[derive(Deserialize)]
struct PcapRun {
    name: String,
    eve: Option<String>,
    error: Option<String>,
    alert_count: Option<usize>,
}

pub(super) fn run(input: &Path, output: &Path) -> Result<()> {
    if output.join("differential.json").exists() {
        let prior: Value = read(&output.join("differential.json"))?;
        if prior["status"] == "failed" {
            return Ok(());
        }
    }
    let reports: Vec<Report> = read(&output.join("conversion.json"))?;
    let et = reports
        .iter()
        .find(|report| report.source == "et_open")
        .ok_or("missing ET report")?;
    if let Some(error) = &et.error {
        return write(
            &output.join("differential.json"),
            &json!({"status":"skipped", "reason":format!("ET Open unavailable: {error}"), "errors":[], "rules":[], "counts":{}, "coverage":{}, "missing_scopes":[], "excluded_pcaps":[]}),
        );
    }
    let metadata: Value = read(&input.join("suricata.json"))?;
    let version = metadata["version"]
        .as_str()
        .ok_or("missing Suricata version")?;
    if version != "7.0.3" {
        return Err(format!("expected Suricata 7.0.3, got {version}").into());
    }
    let expected_hash: String = read(&input.join("et-sha256.json"))?;
    if metadata["et_archive_sha256"] != expected_hash || metadata["home_net"] != json!(HOME_NET) {
        return Err("Suricata and rulec archive bytes or HOME_NET differ".into());
    }
    let bundle_path = input.join("et.bundle");
    let bundle = RuleBundle::from_bytes(
        &fs::read(&bundle_path)
            .map_err(|error| format!("reading {}: {error}", bundle_path.display()))?,
    )?;
    let archive_path = input.join("et.tar.gz");
    let archive = fs::read(&archive_path)
        .map_err(|error| format!("reading {}: {error}", archive_path.display()))?;
    let lines = super::sources::et_lines(&archive)?;
    let infos = RuleInfo::from_rules(bundle.rules(), &lines)?;
    let dropped = &et.summary.as_ref().ok_or("ET summary missing")?.dropped;
    let rejected = rejected_scopes(&lines, dropped);
    let compiled = compile(bundle.into_rules())?;
    let mut matcher = compiled.matcher();
    let home: Vec<Cidr> = HOME_NET
        .iter()
        .map(|s| s.parse())
        .collect::<std::result::Result<_, _>>()?;
    let runs: Vec<PcapRun> = read(&input.join("pcap-runs.json"))?;
    let mut suricata = Hits::new();
    let mut matched = Hits::new();
    let mut available: BTreeMap<_, Vec<Evidence>> = BTreeMap::new();
    let mut excluded = Vec::new();
    let mut counts = BTreeMap::new();
    for run in runs {
        if let Some(error) = run.error {
            excluded.push(json!({"pcap": run.name, "reason":error}));
            continue;
        }
        let path = input.join(run.eve.ok_or("missing EVE path")?);
        let events: Vec<Value> = fs::read_to_string(&path)
            .map_err(|error| format!("reading EVE {}: {error}", path.display()))?
            .lines()
            .map(serde_json::from_str)
            .collect::<std::result::Result<_, _>>()?;
        let flows: BTreeMap<_, _> = events
            .iter()
            .filter(|e| e["event_type"] == "flow")
            .filter_map(|e| e["flow_id"].as_u64().map(|id| (id, e)))
            .collect();
        let mut alerts = 0;
        for event in &events {
            let Some(flow_id) = event["flow_id"].as_u64() else {
                continue;
            };
            let flow = flows.get(&flow_id).copied().unwrap_or(event);
            let tuple = json!({"orig_addr":flow["src_ip"], "orig_port":flow["src_port"], "resp_addr":flow["dest_ip"], "resp_port":flow["dest_port"], "proto":flow["proto"]});
            if event["event_type"] == "alert" {
                alerts += 1;
                // Count every alert, but compare only ET gid=1 signatures.
                if event["alert"]["gid"].as_u64().unwrap_or(1) != 1 {
                    continue;
                }
                if let Some(sid) = event["alert"]["signature_id"].as_u64() {
                    suricata
                        .entry(Key {
                            pcap: run.name.clone(),
                            flow: flow_id,
                            sid: sid.to_string(),
                        })
                        .or_default()
                        .push(Evidence {
                            tuple: tuple.clone(),
                            direction: if event["src_ip"] == flow["src_ip"]
                                && event["src_port"] == flow["src_port"]
                            {
                                Direction::ToServer
                            } else if event["src_ip"] == flow["dest_ip"]
                                && event["src_port"] == flow["dest_port"]
                            {
                                Direction::ToClient
                            } else {
                                Direction::Unknown
                            },
                            kind: event["app_proto"].as_str().unwrap_or("unknown").into(),
                            fields: Vec::new(),
                            missing: BTreeSet::new(),
                        });
                }
            }
            if let Some(record) = records::make(event, flow)
                .map_err(|error| format!("extracting {} flow {flow_id}: {error}", run.name))?
            {
                let kind = format!("{:?}", record.value.kind());
                available
                    .entry((run.name.clone(), flow_id, kind.clone()))
                    .or_default()
                    .push(Evidence {
                        tuple: tuple.clone(),
                        direction: Direction::Unknown,
                        kind: kind.clone(),
                        fields: Vec::new(),
                        missing: record.missing.clone(),
                    });
                for hit in matcher.matches(record.value.as_ref(), &home)? {
                    matched
                        .entry(Key {
                            pcap: run.name.clone(),
                            flow: flow_id,
                            sid: hit.rule().source_rule_id().into(),
                        })
                        .or_default()
                        .push(Evidence {
                            tuple: tuple.clone(),
                            direction: Direction::Unknown,
                            kind: kind.clone(),
                            fields: hit.fields().iter().map(|s| (*s).into()).collect(),
                            missing: record.missing.clone(),
                        });
                }
            }
        }
        counts.insert(run.name, run.alert_count.unwrap_or(alerts));
    }
    let mut result = classify(&infos, &suricata, &matched, &available, dropped, &rejected);
    result.suricata_version = version.into();
    result.et_archive_sha256 = metadata["et_archive_sha256"]
        .as_str()
        .unwrap_or_default()
        .into();
    result.pcap_alert_counts = counts;
    result.excluded_pcaps = excluded;
    if !result.excluded_pcaps.is_empty() {
        result.errors.push("one or more pcaps excluded".into());
    }
    write(&output.join("differential.json"), &result)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn info(sid: &str) -> RuleInfo {
        RuleInfo {
            sid: sid.into(),
            rev: Some(1),
            msg: "test".into(),
            kind: "Http".into(),
            fields: vec!["body.response".into()],
            partial_header: false,
            threshold: false,
            scopes: vec!["http_response".into()],
        }
    }
    fn key(sid: &str, flow: u64) -> Key {
        Key {
            pcap: "sample".into(),
            flow,
            sid: sid.into(),
        }
    }
    fn evidence() -> Vec<Evidence> {
        vec![Evidence {
            tuple: json!(["10.0.0.1", 1234, "1.2.3.4", 80, 6]),
            direction: Direction::ToClient,
            kind: "Http".into(),
            fields: vec!["uri".into()],
            missing: BTreeSet::new(),
        }]
    }

    #[test]
    fn classifies_pairs_rules_marks_drops_and_empty_coverage() {
        let mut infos: Vec<_> = ["1", "2", "3", "4", "5"].map(info).into();
        infos.get_mut(1).unwrap().partial_header = true;
        infos.get_mut(2).unwrap().threshold = true;
        let s = BTreeMap::from([
            (key("1", 1), evidence()),
            (key("2", 1), evidence()),
            (key("4", 1), evidence()),
            (key("5", 1), evidence()),
            (key("99", 1), [evidence(), evidence()].concat()),
        ]);
        let r = BTreeMap::from([
            (key("1", 1), evidence()),
            (key("3", 1), evidence()),
            (key("4", 2), evidence()),
        ]);
        let mut missing = evidence();
        missing
            .first_mut()
            .unwrap()
            .missing
            .insert("body.response".into());
        let available = BTreeMap::from([(("sample".into(), 1, "Http".into()), missing)]);
        let result = classify(
            &infos,
            &s,
            &r,
            &available,
            &BTreeMap::from([("unsupported_keyword:x".into(), vec!["99".into()])]),
            &BTreeMap::new(),
        );
        assert_eq!(
            result.counts,
            BTreeMap::from([
                ("equal".into(), 1),
                ("suricata_only".into(), 2),
                ("rulec_only".into(), 1),
                ("both".into(), 1)
            ])
        );
        assert!(result.rules.get(1).unwrap().input_limit);
        assert!(result.rules.get(2).unwrap().threshold);
        assert!(result.rules.get(4).unwrap().input_limit);
        assert_eq!(result.rules.get(3).unwrap().pairs.len(), 2);
        assert_eq!(
            result.dropped_alerts.get("unsupported_keyword:x").unwrap()["count"],
            2
        );
        assert_eq!(
            result.dropped_alerts.get("unsupported_keyword:x").unwrap()["sids"],
            json!(["99"])
        );
        assert_eq!(result.missing_scopes.len(), 4);
        assert!(!result.errors.is_empty());
        assert_eq!(result.coverage.get("http_response").unwrap().len(), 4);
    }

    #[test]
    fn unmarked_mismatch_with_available_fields_and_complete_coverage() {
        let mut rule = info("1");
        rule.scopes = SCOPES.map(str::to_owned).into();
        let mut events = evidence();
        let mut request = events.first().unwrap().clone();
        request.direction = Direction::ToServer;
        events.push(request);
        let available = BTreeMap::from([(("sample".into(), 1, "Http".into()), evidence())]);
        let result = classify(
            &[rule],
            &BTreeMap::from([(key("1", 1), events)]),
            &BTreeMap::new(),
            &available,
            &BTreeMap::new(),
            &BTreeMap::new(),
        );
        assert!(!result.rules.first().unwrap().input_limit);
        assert!(result.errors.is_empty());
    }

    #[test]
    fn all_rejected_scopes_report_reasons_without_failing() {
        // Neither scope nor SID is special: the decision uses this conversion's
        // accepted rules and rejection reasons, joined to the same source lines.
        let lines = vec![
            br#"alert ssh any any -> any any (flow:to_client; ssh.software; content:"test"; sid:91;)"#.to_vec(),
            br#"alert tls any any -> any any (tls.cert_issuer; content:"test"; sid:92;)"#.to_vec(),
            br#"alert ssh any any -> any any (flow:to_server; ssh.software; content:"test"; sid:93;)"#.to_vec(),
            br#"alert tcp any any -> any any (msg:"ssh.software; sid:94;"; sid:95;)"#.to_vec(),
            br#"alert http any any -> any any (http.uri; content:"test"; sid:96;)"#.to_vec(),
            br#"alert http any any -> any any (http.stat_code; content:"502"; sid:97;)"#.to_vec(),
            br#"alert dns any any -> any any (dns.query; content:"test"; sid:98;)"#.to_vec(),
        ];
        let dropped = BTreeMap::from([
            (
                "needs_state".into(),
                vec![
                    "91".into(),
                    "93".into(),
                    "95".into(),
                    "96".into(),
                    "97".into(),
                    "98".into(),
                ],
            ),
            ("unsupported_regex".into(), vec!["92".into()]),
        ]);
        let rejected = rejected_scopes(&lines, &dropped);
        assert_eq!(
            rejected.get("ssh_server_banner").unwrap(),
            &vec![RejectedRule {
                sid: "91".into(),
                reason: "needs_state".into()
            }]
        );
        for scope in SCOPES {
            let mut covered = info("1");
            covered.scopes = SCOPES
                .iter()
                .filter(|s| **s != scope)
                .map(|s| (*s).into())
                .collect();
            let s = BTreeMap::from([(key("1", 1), evidence())]);
            let result = classify(&[covered], &s, &s, &BTreeMap::new(), &dropped, &rejected);
            assert!(result.errors.is_empty(), "{:?}", result.errors);
            assert!(result.missing_scopes.is_empty());
            assert_eq!(result.no_comparable_rules.get(scope), rejected.get(scope));
        }
    }

    #[test]
    fn accepted_uncovered_scopes_fail_even_with_rejected_candidates() {
        for scope in SCOPES {
            let mut covered = info("1");
            covered.scopes = SCOPES
                .iter()
                .filter(|s| **s != scope)
                .map(|s| (*s).into())
                .collect();
            let mut accepted = info("2");
            accepted.scopes = vec![scope.into()];
            let hits = BTreeMap::from([(key("1", 1), evidence())]);
            let rejected = BTreeMap::from([(
                scope.into(),
                vec![RejectedRule {
                    sid: "91".into(),
                    reason: "needs_state".into(),
                }],
            )]);
            let result = classify(
                &[covered, accepted],
                &hits,
                &hits,
                &BTreeMap::new(),
                &BTreeMap::new(),
                &rejected,
            );
            assert_eq!(result.missing_scopes, vec![scope.to_string()]);
            assert!(!result.no_comparable_rules.contains_key(scope));
            assert!(!result.errors.is_empty());
        }
    }

    #[test]
    fn rejected_scope_options_include_legacy_buffers_and_pcre_flags() {
        let scopes = source_scopes(br#"alert tcp any any -> any any (file_data; pcre:"/test/Q"; tls_cert_subject; dns_query; sid:1;)"#);
        assert_eq!(
            scopes,
            ["http_response", "tls_certificate_response", "dns"]
                .map(str::to_owned)
                .into()
        );
        assert!(
            source_scopes(br#"alert ssh any any -> any any (msg:"ssh.software;"; sid:1;)"#)
                .is_empty()
        );
    }
    #[test]
    fn neutral_ssh_client_alert_does_not_prove_server_coverage() {
        let mut rule = info("1");
        rule.kind = "Ssh".into();
        rule.fields = vec!["client.software".into(), "server.software".into()];
        rule.scopes = vec!["ssh_server_banner".into()];
        let mut events = evidence();
        events.first_mut().unwrap().direction = Direction::ToServer;
        let result = classify(
            &[rule],
            &BTreeMap::from([(key("1", 1), events)]),
            &BTreeMap::new(),
            &BTreeMap::new(),
            &BTreeMap::new(),
            &BTreeMap::new(),
        );
        assert!(result.coverage.get("ssh_server_banner").unwrap().is_empty());
    }

    #[test]
    fn ssh_server_scope_requires_software_instead_of_only_protocol_version() {
        for (buffer, field, software) in [
            ("ssh.proto", "server.proto", false),
            ("ssh_proto", "server.proto", false),
            ("ssh.software", "server.software", true),
            ("ssh_software", "server.software", true),
        ] {
            let line = format!(
                "alert ssh any any -> any any (msg:\"synthetic\"; flow:to_client; {buffer}; content:\"2.0\"; sid:1; rev:1;)"
            )
            .into_bytes();
            let rule = rulec::Rule::from_yaml(&format!(
                "source: et_open\nsource_rule_id: '1'\nmodel: EtSignature\ntitle: synthetic\nlogsource:\n  category: ssh\ndetection:\n  s:\n    {field}: '2.0'\n  condition: s\n"
            ))
            .unwrap();
            let infos = RuleInfo::from_rules(&[rule], std::slice::from_ref(&line)).unwrap();
            assert_eq!(
                infos
                    .first()
                    .unwrap()
                    .scopes
                    .contains(&"ssh_server_banner".into()),
                software,
                "{buffer}"
            );
            assert_eq!(source_scopes(&line).contains("ssh_server_banner"), software);
            let hits = BTreeMap::from([(key("1", 1), evidence())]);
            let result = classify(
                &infos,
                &hits,
                &hits,
                &BTreeMap::new(),
                &BTreeMap::new(),
                &BTreeMap::new(),
            );
            assert_eq!(
                result.coverage.get("ssh_server_banner").unwrap().is_empty(),
                !software,
                "{buffer}"
            );
        }
    }

    #[test]
    fn omitted_certificate_attribute_marks_suricata_only_pair() {
        let mut rule = info("1");
        rule.kind = "Tls".into();
        rule.fields = vec!["subject.joined".into()];
        rule.scopes = vec!["tls_certificate_response".into()];
        let event = json!({"event_type":"tls", "tls":{
            "subject":"C=US, O=Example, OU=Lost, CN=example.invalid"
        }});
        let record = records::make(&event, &json!({})).unwrap().unwrap();
        let mut events = evidence();
        let event = events.first_mut().unwrap();
        event.kind = "Tls".into();
        event.missing = record.missing;
        let available = BTreeMap::from([(("sample".into(), 1, "Tls".into()), events)]);
        let result = classify(
            &[rule],
            &BTreeMap::from([(key("1", 1), evidence())]),
            &Hits::new(),
            &available,
            &BTreeMap::new(),
            &BTreeMap::new(),
        );
        let rule = result.rules.first().unwrap();
        assert_eq!(rule.classification, "suricata_only");
        assert!(rule.input_limit);
        assert!(rule.pairs.first().unwrap().input_limit);
    }

    #[test]
    fn dns_answer_availability_controls_suricata_only_input_limit() {
        for (answers, field, incomplete) in [
            (
                json!([{"rdata":"example.invalid", "ttl":60}, {}]),
                "answer",
                true,
            ),
            (
                json!([{"rdata":"example.invalid", "ttl":4294967295_u64}]),
                "ttl",
                true,
            ),
            (
                json!([{"rdata":"example.invalid", "ttl":60}]),
                "answer",
                false,
            ),
            (json!([]), "answer", false),
        ] {
            let record = records::make(
                &json!({"event_type":"dns", "dns":{"answers":answers}}),
                &json!({}),
            )
            .unwrap()
            .unwrap();
            let mut rule = info("1");
            rule.kind = "Dns".into();
            rule.fields = vec![field.into()];
            rule.scopes = vec!["dns".into()];
            let mut events = evidence();
            let event = events.first_mut().unwrap();
            event.kind = "Dns".into();
            event.missing = record.missing;
            let available = BTreeMap::from([(("sample".into(), 1, "Dns".into()), events)]);
            let result = classify(
                &[rule],
                &BTreeMap::from([(key("1", 1), evidence())]),
                &Hits::new(),
                &available,
                &BTreeMap::new(),
                &BTreeMap::new(),
            );
            let rule = result.rules.first().unwrap();
            assert_eq!(rule.classification, "suricata_only");
            assert_eq!(rule.input_limit, incomplete, "{field}: {answers}");
            assert_eq!(rule.pairs.first().unwrap().input_limit, incomplete);
        }
    }

    #[test]
    fn offline_end_to_end_conversion_records_and_all_five_scopes() {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("work");
        let output = directory.path().join("results");
        fs::create_dir(&input).unwrap();
        let mut all = String::new();
        for (id, protocol, conditions) in [
            (1, "http", "http.uri; content:\"/probe\";"),
            (
                2,
                "http",
                "flow:established,to_client; http.stat_code; content:\"502\";",
            ),
            (
                3,
                "tls",
                "flow:established,to_client; tls.cert_subject; content:\"CN=example.invalid\";",
            ),
            (
                4,
                "ssh",
                "flow:established,to_client; ssh.software; content:\"Probe\";",
            ),
            (5, "dns", "dns.query; content:\"example.invalid\";"),
        ] {
            // All signatures are handwritten test definitions, not upstream rules.
            let text = format!(
                "alert {protocol} any any -> any any (msg:\"synthetic {id}\"; {conditions} sid:{id}; rev:1; metadata:updated_at 2026_01_01;)\n"
            );
            all.push_str(&text);
        }
        let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut tar = tar::Builder::new(encoder);
        let mut header = tar::Header::new_gnu();
        header.set_size(u64::try_from(all.len()).unwrap());
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(&mut header, "rules/emerging-dns.rules", all.as_bytes())
            .unwrap();
        fs::write(
            input.join("et.tar.gz"),
            tar.into_inner().unwrap().finish().unwrap(),
        )
        .unwrap();
        write(
            &input.join("sources.json"),
            &json!([{ "source":"et_open", "path":"et.tar.gz", "version":"1", "error":null }]),
        )
        .unwrap();
        super::super::sources::run(&input, &output).unwrap();
        let report: Report = read(&output.join("et_open.json")).unwrap();
        assert!(report.error.is_none(), "{:?}", report.error);
        assert_eq!(report.input_count, 5);
        let digest: String = read(&input.join("et-sha256.json")).unwrap();
        write(
            &input.join("suricata.json"),
            &json!({"version":"7.0.3", "et_archive_sha256":digest, "home_net":HOME_NET}),
        )
        .unwrap();
        let mut events = Vec::new();
        for (flow, kind, value) in [
            (
                1,
                "http",
                json!({"http_method":"GET", "url":"/probe", "status":502}),
            ),
            (2, "tls", json!({"subject":"CN=example.invalid"})),
            (
                3,
                "ssh",
                json!({"server":{"proto_version":"2.0", "software_version":"Probe"}}),
            ),
            (4, "dns", json!({"rrname":"example.invalid", "rrtype":"A"})),
        ] {
            let mut event = json!({"event_type":kind, "flow_id":flow, "src_ip":"10.0.0.1", "dest_ip":"198.51.100.1", "src_port":1234, "dest_port":80, "proto":"TCP"});
            event[kind] = value;
            events.push(event.clone());
            event["event_type"] = json!("flow");
            event["app_proto"] = json!(kind);
            events.push(event.clone());
            for sid in match flow {
                1 => vec![1, 2],
                2 => vec![3],
                3 => vec![4],
                _ => vec![5],
            } {
                event["event_type"] = json!("alert");
                event["alert"] = json!({"gid":1,"signature_id":sid});
                let mut alert = event.clone();
                if matches!(sid, 2..=4) {
                    alert["src_ip"] = json!("198.51.100.1");
                    alert["src_port"] = json!(80);
                    alert["dest_ip"] = json!("10.0.0.1");
                    alert["dest_port"] = json!(1234);
                }
                events.push(alert);
            }
        }
        fs::write(
            input.join("eve.json"),
            events.iter().map(|v| format!("{v}\n")).collect::<String>(),
        )
        .unwrap();
        write(
            &input.join("pcap-runs.json"),
            &json!([{ "name":"synthetic", "eve":"eve.json", "error":null }]),
        )
        .unwrap();
        run(&input, &output).unwrap();
        let differential: Differential = read(&output.join("differential.json")).unwrap();
        assert!(differential.errors.is_empty(), "{:?}", differential.errors);
        assert_eq!(differential.counts.get("equal"), Some(&5));
        assert_eq!(differential.pcap_alert_counts.get("synthetic"), Some(&5));
        assert!(
            differential
                .coverage
                .values()
                .all(|rules| !rules.is_empty())
        );
        for entry in fs::read_dir(output).unwrap() {
            let text = fs::read_to_string(entry.unwrap().path()).unwrap();
            assert!(!text.contains("detection:"));
            assert!(!text.contains("alert http"));
        }
    }
}

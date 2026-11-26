//! Compile time, database size and matching throughput.
//!
//! The synthetic measurement compiles 1,000 rules for each of the five
//! network kinds — literals, regular expressions, numbers, `cidr` and
//! derived fields mixed — and matches synthetic records of each kind.
//!
//! Setting both `RULEC_BENCH_RULES` and `RULEC_BENCH_RECORDS` runs the
//! same measurement on local data as well:
//!
//! - `RULEC_BENCH_RULES` is a directory of Clumit Sigma files (`.yml`,
//!   `.yaml`), or one rule bundle file as `RuleBundle::to_bytes` writes it.
//! - `RULEC_BENCH_RECORDS` is a directory of `<kind>.jsonl` files (`conn`,
//!   `dns`, `http`, `ssh`, `tls`), each line one `giganto-client` record
//!   written with `serde_json`. A missing file is skipped.

use std::{
    env, fs,
    hint::black_box,
    net::{IpAddr, Ipv4Addr},
    path::{Path, PathBuf},
};

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use giganto_client::ingest::network::{Conn, Dns, Http, Ssh, Tls};
use rulec::{CompiledRules, Event, Rule, RuleBundle, compile};
use serde::de::DeserializeOwned;

const RULES_PER_KIND: usize = 1_000;
const RECORDS_PER_KIND: usize = 256;
const RULES_VAR: &str = "RULEC_BENCH_RULES";
const RECORDS_VAR: &str = "RULEC_BENCH_RECORDS";

/// The fields one kind's synthetic rules test.
struct KindFields {
    kind: &'static str,
    /// Fields holding text, for literal and regular expression conditions.
    text: [&'static str; 2],
    /// A field holding an integer.
    number: &'static str,
    /// A field holding an address.
    addr: &'static str,
    /// Derived fields, or more text fields for a kind without any.
    derived: [&'static str; 2],
}

const KIND_FIELDS: [KindFields; 5] = [
    KindFields {
        kind: "conn",
        text: ["service", "conn_state"],
        number: "orig_bytes",
        addr: "resp_addr",
        derived: ["service", "conn_state"],
    },
    KindFields {
        kind: "dns",
        text: ["query", "answer"],
        number: "qtype",
        addr: "resp_addr",
        derived: ["query", "answer"],
    },
    KindFields {
        kind: "http",
        text: ["uri", "user_agent"],
        number: "status_code",
        addr: "resp_addr",
        derived: ["uri.normalized", "header_block"],
    },
    KindFields {
        kind: "tls",
        text: ["server_name", "ja3"],
        number: "cipher",
        addr: "resp_addr",
        derived: ["subject.joined", "issuer.joined"],
    },
    KindFields {
        kind: "ssh",
        text: ["client", "hassh"],
        number: "resp_port",
        addr: "resp_addr",
        derived: ["client.software", "server.software"],
    },
];

/// Returns the token the `i`-th synthetic rule and record share.
fn token(i: usize) -> String {
    format!("tok{:04}", i % RULES_PER_KIND)
}

/// Returns the detection of the `i`-th synthetic rule of a kind.
fn detection(f: &KindFields, i: usize) -> String {
    let t = token(i);
    let [text_a, text_b] = f.text;
    let [derived_a, derived_b] = f.derived;
    let selection = match i % 8 {
        0 => format!("        {text_a}|contains: '{t}'\n"),
        1 => format!("        {text_b}|endswith: '{t}'\n"),
        2 => format!("        {text_a}|re: '{t}[0-9]{{2,}}'\n"),
        3 => format!(
            "        {text_b}|contains: '{t}'\n        {}|gte: {}\n",
            f.number,
            i % 300
        ),
        4 => format!(
            "        {text_a}|startswith: '{t}'\n        {}|cidr: 10.{}.0.0/16\n",
            f.addr,
            i % 256
        ),
        5 => format!("        {derived_a}|contains: '{t}'\n"),
        6 => format!("        {derived_b}|contains|all:\n            - '{t}'\n            - 'x'\n"),
        // A few rules no pattern decides, checked for every record.
        _ if i % 64 == 7 => format!("        {}|cidr: 192.0.2.0/24\n", f.addr),
        _ => format!("        {derived_a}|re|i: '{t}-[a-z]+'\n"),
    };
    format!("    sel:\n{selection}    condition: sel\n")
}

fn synthetic_rules() -> Vec<Rule> {
    let mut rules = Vec::with_capacity(RULES_PER_KIND * KIND_FIELDS.len());
    for f in &KIND_FIELDS {
        for i in 0..RULES_PER_KIND {
            let text = format!(
                "title: bench {kind} {i}\nsource: sigma_hq\nsource_rule_id: '{kind}-{i}'\n\
                 model: SigmaSignature\nlogsource:\n    category: {kind}\ndetection:\n{}",
                detection(f, i),
                kind = f.kind,
            );
            match Rule::from_yaml(&text) {
                Ok(rule) => rules.push(rule),
                Err(e) => panic!("synthetic rule {} {i} does not read: {e}", f.kind),
            }
        }
    }
    rules
}

/// Returns a text that holds a rule token for one record in eight.
fn varied(j: usize, prefix: &str) -> String {
    if j.is_multiple_of(8) {
        format!("{prefix}{}42-x", token(j * 37))
    } else {
        format!("{prefix}plain{j}")
    }
}

fn addr(j: usize) -> IpAddr {
    let j = u8::try_from(j % 256).unwrap_or_default();
    IpAddr::V4(Ipv4Addr::new(10, j, 1, j))
}

fn u16_of(j: usize) -> u16 {
    u16::try_from(j % 65_536).unwrap_or_default()
}

fn synthetic_conn(j: usize) -> Conn {
    Conn {
        orig_addr: addr(j + 1),
        orig_port: 40_000,
        resp_addr: addr(j),
        resp_port: 80,
        proto: 6,
        conn_state: varied(j, "S"),
        start_time: 0,
        duration: 1,
        service: varied(j + 1, "svc-"),
        orig_bytes: u64::try_from(j).unwrap_or_default(),
        resp_bytes: 2,
        orig_pkts: 3,
        resp_pkts: 4,
        orig_l2_bytes: 5,
        resp_l2_bytes: 6,
    }
}

fn synthetic_dns(j: usize) -> Dns {
    Dns {
        orig_addr: addr(j + 1),
        orig_port: 40_000,
        resp_addr: addr(j),
        resp_port: 53,
        proto: 17,
        start_time: 0,
        duration: 1,
        orig_pkts: 1,
        resp_pkts: 1,
        orig_l2_bytes: 80,
        resp_l2_bytes: 120,
        query: varied(j, "www.") + ".example.com",
        answer: vec![varied(j + 3, "a-"), "192.0.2.1".to_string()],
        trans_id: u16_of(j),
        rtt: 10,
        qclass: 1,
        qtype: u16_of(j % 30),
        rcode: 0,
        aa_flag: false,
        tc_flag: false,
        rd_flag: true,
        ra_flag: true,
        ttl: vec![300],
    }
}

fn synthetic_http(j: usize) -> Http {
    Http {
        orig_addr: addr(j + 1),
        orig_port: 40_000,
        resp_addr: addr(j),
        resp_port: 80,
        proto: 6,
        start_time: 0,
        duration: 1,
        orig_pkts: 1,
        resp_pkts: 1,
        orig_l2_bytes: 500,
        resp_l2_bytes: 1500,
        method: if j.is_multiple_of(2) { "GET" } else { "POST" }.to_string(),
        host: format!("Host{j}.Example.com:8080"),
        uri: varied(j, "/static/./a//b/../") + "?q=%41",
        referer: String::new(),
        version: "1.1".to_string(),
        user_agent: varied(j + 2, "Mozilla/5.0 "),
        request_len: 400,
        response_len: 1200,
        status_code: u16_of(200 + j % 300),
        status_msg: "OK".to_string(),
        username: String::new(),
        password: String::new(),
        cookie: String::new(),
        content_encoding: String::new(),
        content_type: "text/plain".to_string(),
        cache_control: String::new(),
        filenames: Vec::new(),
        mime_types: Vec::new(),
        body: varied(j + 5, "a=1&b=").into_bytes(),
        state: String::new(),
        request_header_names: vec![
            "Host".to_string(),
            "User-Agent".to_string(),
            "Accept".to_string(),
        ],
        accept: varied(j + 4, "text/"),
        connection: "keep-alive".to_string(),
        accept_encoding: String::new(),
        accept_language: String::new(),
        pragma: String::new(),
    }
}

fn synthetic_tls(j: usize) -> Tls {
    Tls {
        orig_addr: addr(j + 1),
        orig_port: 40_000,
        resp_addr: addr(j),
        resp_port: 443,
        proto: 6,
        start_time: 0,
        duration: 1,
        orig_pkts: 1,
        resp_pkts: 1,
        orig_l2_bytes: 500,
        resp_l2_bytes: 1500,
        server_name: varied(j, "www.") + ".example.com",
        alpn_protocol: "h2".to_string(),
        ja3: varied(j + 1, "771,4865-"),
        version: "TLSv1.3".to_string(),
        client_cipher_suites: vec![4865, 4866],
        client_extensions: vec![0, 23],
        cipher: u16_of(4865 + j % 3),
        extensions: vec![43],
        ja3s: String::new(),
        serial: "01".to_string(),
        subject_country: "US".to_string(),
        subject_org_name: varied(j + 2, "Org "),
        subject_common_name: format!("host{j}.example.com"),
        validity_not_before: 0,
        validity_not_after: 1,
        subject_alt_name: String::new(),
        issuer_country: "US".to_string(),
        issuer_org_name: "CA".to_string(),
        issuer_org_unit_name: varied(j + 3, "Unit "),
        issuer_common_name: "CA R1".to_string(),
        last_alert: 0,
    }
}

fn synthetic_ssh(j: usize) -> Ssh {
    Ssh {
        orig_addr: addr(j + 1),
        orig_port: 40_000,
        resp_addr: addr(j),
        resp_port: 22,
        proto: 6,
        start_time: 0,
        duration: 1,
        orig_pkts: 1,
        resp_pkts: 1,
        orig_l2_bytes: 500,
        resp_l2_bytes: 1500,
        client: varied(j, "SSH-2.0-OpenSSH_") + " Ubuntu",
        server: varied(j + 1, "SSH-2.0-dropbear_"),
        cipher_alg: "aes128-ctr".to_string(),
        mac_alg: "hmac-sha2-256".to_string(),
        compression_alg: "none".to_string(),
        kex_alg: "curve25519-sha256".to_string(),
        host_key_alg: "ssh-ed25519".to_string(),
        hassh_algorithms: String::new(),
        hassh: varied(j + 2, "h"),
        hassh_server_algorithms: String::new(),
        hassh_server: String::new(),
        client_shka: String::new(),
        server_shka: String::new(),
    }
}

fn records<T>(make: fn(usize) -> T) -> Vec<T> {
    (0..RECORDS_PER_KIND).map(make).collect()
}

/// Prints the statistics of a compilation.
fn report(label: &str, compiled: &CompiledRules) {
    let stats = compiled.stats();
    println!(
        "{label}: {} rules compiled, {} excluded, in {:?}; vectorscan databases {} bytes",
        stats.accepted(),
        stats.excluded().len(),
        stats.compile_time(),
        stats.db_size()
    );
}

/// Measures matching `records` against `compiled`, in records per second.
fn bench_records<E: Event>(
    c: &mut Criterion,
    group: &str,
    kind: &str,
    compiled: &CompiledRules,
    records: &[E],
) {
    if records.is_empty() {
        return;
    }
    let mut group = c.benchmark_group(group);
    group.throughput(Throughput::Elements(
        u64::try_from(records.len()).unwrap_or(u64::MAX),
    ));
    let mut matcher = compiled.matcher();
    group.bench_function(kind, |b| {
        b.iter(|| {
            let mut matched = 0_usize;
            for record in records {
                match matcher.matches(black_box(record), &[]) {
                    Ok(m) => matched += m.len(),
                    Err(e) => panic!("matching a {kind} record: {e}"),
                }
            }
            black_box(matched)
        });
    });
    group.finish();
}

fn synthetic(c: &mut Criterion) {
    let compiled = match compile(synthetic_rules()) {
        Ok(compiled) => compiled,
        Err(e) => panic!("compiling the synthetic rules: {e}"),
    };
    report("synthetic", &compiled);
    bench_records(c, "synthetic", "conn", &compiled, &records(synthetic_conn));
    bench_records(c, "synthetic", "dns", &compiled, &records(synthetic_dns));
    bench_records(c, "synthetic", "http", &compiled, &records(synthetic_http));
    bench_records(c, "synthetic", "tls", &compiled, &records(synthetic_tls));
    bench_records(c, "synthetic", "ssh", &compiled, &records(synthetic_ssh));
}

/// Reads the rules at `path`: a directory of Clumit Sigma files, or a rule
/// bundle file. Rules that do not read are counted and skipped.
fn read_rules(path: &Path) -> Vec<Rule> {
    if path.is_dir() {
        let entries = match fs::read_dir(path) {
            Ok(entries) => entries,
            Err(e) => panic!("reading {}: {e}", path.display()),
        };
        let mut files: Vec<PathBuf> = entries
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|p| {
                p.extension()
                    .is_some_and(|ext| ext == "yml" || ext == "yaml")
            })
            .collect();
        files.sort_unstable();
        let mut rules = Vec::with_capacity(files.len());
        let mut unread = 0_usize;
        for file in &files {
            let text = match fs::read_to_string(file) {
                Ok(text) => text,
                Err(e) => panic!("reading {}: {e}", file.display()),
            };
            match Rule::from_yaml(&text) {
                Ok(rule) => rules.push(rule),
                Err(_) => unread += 1,
            }
        }
        println!(
            "{}: {} rules read, {unread} not",
            path.display(),
            rules.len()
        );
        rules
    } else {
        let bytes = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(e) => panic!("reading {}: {e}", path.display()),
        };
        match RuleBundle::from_bytes(&bytes) {
            Ok(bundle) => bundle.into_rules(),
            Err(e) => panic!("reading the rule bundle {}: {e}", path.display()),
        }
    }
}

/// Reads `<kind>.jsonl` in `dir`, or nothing if there is no such file.
fn read_records<T: DeserializeOwned>(dir: &Path, kind: &str) -> Vec<T> {
    let path = dir.join(format!("{kind}.jsonl"));
    if !path.exists() {
        return Vec::new();
    }
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) => panic!("reading {}: {e}", path.display()),
    };
    text.lines()
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty())
        .map(|(n, line)| match serde_json::from_str(line) {
            Ok(record) => record,
            Err(e) => panic!("{} line {}: {e}", path.display(), n + 1),
        })
        .collect()
}

fn local(c: &mut Criterion) {
    let (Some(rules), Some(records)) = (env::var_os(RULES_VAR), env::var_os(RECORDS_VAR)) else {
        return;
    };
    let (rules, records) = (PathBuf::from(rules), PathBuf::from(records));
    let compiled = match compile(read_rules(&rules)) {
        Ok(compiled) => compiled,
        Err(e) => panic!("compiling the rules of {}: {e}", rules.display()),
    };
    report("local", &compiled);
    let conn: Vec<Conn> = read_records(&records, "conn");
    let dns: Vec<Dns> = read_records(&records, "dns");
    let http: Vec<Http> = read_records(&records, "http");
    let tls: Vec<Tls> = read_records(&records, "tls");
    let ssh: Vec<Ssh> = read_records(&records, "ssh");
    bench_records(c, "local", "conn", &compiled, &conn);
    bench_records(c, "local", "dns", &compiled, &dns);
    bench_records(c, "local", "http", &compiled, &http);
    bench_records(c, "local", "tls", &compiled, &tls);
    bench_records(c, "local", "ssh", &compiled, &ssh);
}

criterion_group!(benches, synthetic, local);
criterion_main!(benches);

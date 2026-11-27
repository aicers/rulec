# Daily conversion and differential checks

[The daily workflow](../.github/workflows/daily.yml) runs once daily, on
manual dispatch, and on pull requests changing its implementation or
inputs. A single concurrency group serializes all runs. It is independent
of `ci.yml` and `CI Gate`, and is not a required branch check.

The workflow downloads ET Open's Suricata 7.0.3 archive and adjacent
`version.txt`, SigmaHQ's latest `sigma_all_rules.zip` and release
`tag_name`, and the emerging-threats source archive at the last commit
changing that directory. Archives remain in the runner's working directory.
The Rust example consumes local files; the library and Rust tests never
make network requests. Only development dependencies support the example.

## Conversion audit and history

For every source the example writes the unmodified conversion summary,
its independently counted input total, accepted IDs, and an optional
failure reason. It checks that accepted model counts plus dropped reason
counts equal the input total, that accepted counts equal the rule list,
that a dropped ID has exactly one entry/reason, and that recompilation of
the complete accepted list excludes no rules.

The independent ET reader includes only regular `.rules` files directly
under `rules/`, allowing leading `./`. It excludes retired and reputation
files exactly as listed in `src/lib.rs`; comments and blank lines are
ignored, and backslash continuations are one rule. The independent Sigma
reader selects release `rules/**` (excluding `deprecated` directories) or
`rules-emerging-threats/**`, at the root or in the archive's top directory.
YAML documents with status `deprecated` or `unsupported` are not inputs.
Malformed selected YAML still counts as an input to be rejected.

The baseline is the last successful **scheduled** run on the default
branch, excluding the current run. Manual and PR runs never become the
baseline. `changes.json` records source and rulec versions before/after,
model and rejection-reason count deltas, newly dropped IDs, and newly
accepted IDs. The initial run explicitly reports no baseline. A missing,
expired, or unreadable artifact on an existing baseline is recorded as
an unavailable comparison with its reason. It never silently substitutes
an older run or calls a retrieval failure the first run.

## Reference engine and public corpus

The reference engine is Ubuntu 24.04's apt package
`suricata=1:7.0.3-1build3`; the runner verifies `suricata -V` reports exactly
`7.0.3`. [The overrides](../.github/daily/suricata.yaml) replace EVE
output settings and disable Ubuntu's system command socket: offline replay
needs no control socket or permission to write under `/var/run`.
`--set vars.address-groups.HOME_NET=...` preserves all
sibling default variables. Both engines use the unchanged 7.0.3 defaults
`192.168.0.0/16`, `10.0.0.0/8`, `172.16.0.0/12`. The report checks that the
archive SHA-256 and HOME_NET actually recorded by both stages agree.
Suricata's rules come from the exact archive bytes converted by rulec,
using the same included-file scope. No updater or extra rule source runs.
`--init-errors-fatal` rejects partial signature loading. `-k none` disables
packet checksum validation for offline captures, not protocol inspection.

[The manifest](../.github/daily/pcaps.json) records URLs, SHA-256, provenance,
redistribution terms, and record kind/direction for every pcap. Captures
are checked before replay; a changed digest is never used.

- `protocol-probes.pcap` is this public repository's Apache-2.0 synthetic
  corpus, published with this change. Its source is
  [make_probes.py](../.github/daily/make_probes.py), which reproduces every
  byte using the Python standard library without network I/O. It contains
  only private/documentation addresses and synthetic HTTP, SSH, and DNS.
  The deliberately nested SSH software string exercises a signature that
  looks for a full banner inside the software portion. This is a protocol
  stimulus, not a production traffic sample. CI downloads the pcap from
  the PR head repository/revision; local replay can use the bundled copy.
- The TLS certificate capture is pinned to a commit of OISF's
  `suricata-verify`, under its
  [MIT license](https://github.com/OISF/suricata-verify/blob/923478ed7df163c6b126a07e841bc38ecba045d8/LICENSE.txt).
  Follow that notice's copyright/permission requirements if redistributing
  it. The pcap remains a temporary download, outside artifacts and git.

The fixed probes are not altered to follow the current rule set. Coverage
is measured afresh each run: an accepted ET rule must actually alert in
Suricata in each of these five scopes: HTTP request, HTTP response,
TLS certificate response (`subject.joined`/`issuer.joined`), SSH server
banner, and DNS. Each scope lists the observed accepted SIDs and their
classifications. A direction-neutral SSH rule only establishes server
coverage when a Suricata alert is oriented from server to client; a
client-banner alert cannot establish that scope. When the converter accepts
at least one rule for a scope but Suricata fires none, that coverage gap
fails the run. If every source rule for a scope is rejected instead, the
result's `no_comparable_rules` and run summary report **no comparable rule**
with every rejected SID and its actual conversion reason; this does not
fail the run. Source option names (including legacy buffer names and HTTP
PCRE buffer flags), flow direction, accepted fields, and rejection IDs from
the same archive determine this distinction anew, without special cases
for a scope or source version. Quoted messages and content are not syntax.
An absent or unrecognized scope without rejected candidates still fails.
More corpus entries can be added
in a normal reviewed PR, with provenance, licensing and checksum.

## Record extraction: every field's provenance

Suricata 7.0.3 is also the public pcap decoder. Its EVE protocol events
become actual `giganto-client` `Http`, `Dns`, `Tls`, `Ssh`, and `Conn`
records, which are passed through the library's existing `Event`
implementations. This intentionally shares protocol parsing with the
reference engine; the comparison tests conversion and matching, not an
independent packet parser. EVE fields follow the
[7.0.3 EVE format](https://docs.suricata.io/en/suricata-7.0.3/output/eve/eve-json-format.html).
No values are inferred from a signature or from whether it alerted.

Each protocol event emits one record; every EVE `flow` emits one `Conn`.
The final EVE flow record supplies client/server orientation for all
records and alerts sharing its `flow_id`. A missing final flow record uses
the event tuple, and unavailable values remain empty. The identity is
`(pcap name, EVE flow_id, sid)`, retaining the oriented five-tuple in
results. Distinct flows reusing a five-tuple remain distinct. Transactions
and repeated alerts within one flow collapse to the specified flow unit.

“Empty” below means `""`, `[]`, `0` or `false`, according to the existing
record type. Unknown protocols and unparseable or out-of-range times also stay empty.
The example separately tracks unavailable fields, including
derived dependencies, so those placeholder values do not hide extraction
limits. A supplied empty value is distinguished from an unavailable one.

### Common fields of all five kinds

<!-- Tables keep each field/source mapping on one row. -->
<!-- markdownlint-disable MD013 -->
| Record field | Source or empty |
| --- | --- |
| `orig_addr`, `orig_port` | Final EVE flow `src_ip`, `src_port` |
| `resp_addr`, `resp_port` | Final EVE flow `dest_ip`, `dest_port` |
| `proto` | EVE flow protocol: TCP=6, UDP=17, ICMP=1, IPv6-ICMP=58; others empty |
| `start_time` | `flow.start`, UTC Unix nanoseconds |
| `duration` | `flow.end - flow.start`, nanoseconds |
| `orig_pkts`, `resp_pkts` | `flow.pkts_toserver`, `flow.pkts_toclient` |
| `orig_l2_bytes`, `resp_l2_bytes` | Empty; EVE byte counters are not layer-2 byte counts |
<!-- markdownlint-enable MD013 -->

### Conn

| Record field | Source or empty |
| --- | --- |
| `service` | EVE `app_proto` |
| `conn_state` | Empty; EVE TCP state is not a Zeek connection state |
| `orig_bytes`, `resp_bytes` | Empty; EVE flow counters include headers |

### Http

<!-- Tables keep each field/source mapping on one row. -->
<!-- markdownlint-disable MD013 -->
| Record field | Source or empty |
| --- | --- |
| `method`, `host`, `uri` | `http.http_method`, `http.hostname`, `http.url` |
| `referer`, `version`, `user_agent` | `http.http_refer`, `http.protocol`, `http.http_user_agent` |
| `status_code` | `http.status` |
| `request_len`, `response_len`, `status_msg` | Empty |
| `username`, `password`, `cookie` | Empty |
| `content_encoding`, `content_type`, `cache_control` | Empty; response EVE content type is not a request header |
| `filenames`, `mime_types`, `body`, `state` | Empty; EVE does not provide complete body bytes |
| `request_header_names`, `accept`, `connection` | Empty |
| `accept_encoding`, `accept_language`, `pragma` | Empty |
| `uri.normalized`, `host.normalized` | Existing rulec normalization of `uri`, `host` |
| `body.request`, `body.response` | Empty, because `body` is empty |
| `header_names.joined`, `header_block` | Empty, because request header names are unavailable |
<!-- markdownlint-enable MD013 -->

### Dns

<!-- Tables keep each field/source mapping on one row. -->
<!-- markdownlint-disable MD013 -->
| Record field | Source or empty |
| --- | --- |
| `query` | `dns.rrname`, or first `dns.queries[].rrname` in response |
| `answer` | `dns.answers[].rdata` strings |
| `trans_id` | `dns.id` |
| `qtype` | `rrtype` of query (or first response query): A, NS, CNAME, SOA, PTR, MX, TXT, AAAA, SRV, ANY, or a numeric string; others empty |
| `rcode` | `dns.rcode`: NOERROR=0, SERVFAIL=2, NXDOMAIN=3, numeric string; others empty |
| `ttl` | `dns.answers[].ttl` representable as i32 |
| `rtt`, `qclass`, `aa_flag`, `tc_flag`, `rd_flag`, `ra_flag` | Empty |
<!-- markdownlint-enable MD013 -->

### Tls

<!-- Tables keep each field/source mapping on one row. -->
<!-- markdownlint-disable MD013 -->
| Record field | Source or empty |
| --- | --- |
| `server_name`, `version`, `serial` | `tls.sni`, `tls.version`, `tls.serial` |
| `ja3`, `ja3s` | `tls.ja3.hash`, `tls.ja3s.hash` when present |
| `subject_country`, `subject_org_name`, `subject_common_name` | Unique `C`, `O`, `CN` in `tls.subject` |
| `issuer_country`, `issuer_org_name`, `issuer_org_unit_name`, `issuer_common_name` | Unique `C`, `O`, `OU`, `CN` in `tls.issuerdn` |
| `validity_not_before`, `validity_not_after` | `tls.notbefore`, `tls.notafter`, Unix seconds; EVE dates without an offset are UTC |
| `subject_alt_name` | Empty |
| `alpn_protocol`, `client_cipher_suites`, `client_extensions` | Empty |
| `cipher`, `extensions`, `last_alert` | Empty |
| `subject.joined`, `issuer.joined` | Existing rulec joining of the certificate component fields |
<!-- markdownlint-enable MD013 -->

Certificate RDN parsing accepts only unambiguous comma-space separated
names. Escapes, multi-valued RDNs (`+`), duplicate components, and absent
components stay empty. Subject organizational units have no field in the
record and cannot be preserved. These are extraction limits, not guessed
certificate identities.

### Ssh

<!-- Tables keep each field/source mapping on one row. -->
<!-- markdownlint-disable MD013 -->
| Record field | Source or empty |
| --- | --- |
| `client`, `server` | `SSH-` + EVE `ssh.client/server.proto_version` + `-` + `software_version` |
| `cipher_alg`, `mac_alg`, `compression_alg`, `kex_alg`, `host_key_alg` | Empty |
| `hassh_algorithms`, `hassh`, `hassh_server_algorithms`, `hassh_server` | Empty |
| `client_shka`, `server_shka` | Empty |
| `client.proto`, `client.software`, `server.proto`, `server.software` | Existing rulec banner splitting of `client` and `server` |
<!-- markdownlint-enable MD013 -->

## Classification and failures

Each observed `(pcap, flow, sid)` is `equal`, `suricata_only`, or
`rulec_only`. A rule is `equal` when no pair differs, including a rule
that never fires. Otherwise it is `suricata_only`, `rulec_only`, or `both`
when different pairs disagree in both directions. Only mismatched pairs
need evidence in the result; they include pcap, flow ID, five-tuple, record
kind and, for rulec hits, the fields whose conditions were true.

A Suricata-only pair has an **input limit** mark if its rule satisfies the
library's exact `header_values_partly_missing` definition, or all candidate
records of that kind in the flow lack a field the rule uses. If no record
of that kind exists, all of its fields are unavailable. The public
`inspect_et_open_rule` API uses the converter's parser and header test;
`Rule::fields` exposes all used fields, including field references. No
per-rule meaning is guessed from an aggregate counter.

A rulec-only pair has a **threshold** mark when the original rule contains
`threshold` or `detection_filter`, which rulec ignores. Marks are aggregated
to the rule if any mismatched pair carries them. Alerts on rejected rules
are separate: counts and distinct SIDs per rejection reason. Repeated
alerts count individually there; they never become mismatches.

A source download/conversion/audit failure records that source's error,
continues the other sources and fails the run at the final status step.
An ET failure explicitly skips differential checks, records the reason
and still retains Sigma results. A pcap download/hash/replay failure
excludes only that pcap, records its reason, replays the rest and fails
the run. Wrong Suricata version, extraction errors, archive/HOME_NET
disagreement, or a coverage gap with accepted rules also fail. A scope
whose source rules were all rejected is reported without failing, as
described above. **Disagreement alone
does not fail the run.**

## Artifacts, issue filing and follow-up

The `daily-results` artifact contains only source reports,
`conversion.json`, `changes.json`, `differential.json`, `status.json`, and
`summary.md`; public-repository retention is the maximum 90 days.
`$GITHUB_STEP_SUMMARY` shows model/rejection counts, differential counts,
coverage SIDs, excluded pcaps and failure/skip reasons. Archives, original
or converted rules, serialized bundles, records, pcaps and raw Suricata
logs are never uploaded. In particular, signatures printed in Suricata
error logs never enter public artifacts or console logs.

The read-only planning job writes candidate Korean issue titles and
bodies to `daily-issue-plan`. The publishing job alone has `issues: write`,
and runs only for a schedule on the default branch. Manual and PR runs
only plan. It queries all issues (open **and** closed, excluding PRs),
checks again immediately before each creation, verifies the created
issue with a structured read, and creates at most 20 issues. Retries
sharing the same run URL subtract
issues already created by that run, including closed issues, from its
quota. Artifact uploads replace the earlier attempt of the same run.
The durable key is this exact HTML comment:

```text
<!-- rulec-differential:sid=123456;rev=7 -->
```

Keep the marker when editing an issue. Closing an issue does not permit a
new issue for the same SID/revision; a different revision is a different
key. Equal or marked rules are excluded. Candidates beyond 20 are listed
as deferred and reconsidered on the next run. Bodies contain only SID,
revision, message, classification, mismatched pcaps/flows, run URL and
source/rulec versions; no original or converted signature is included.
`daily-filed-issues` records creation URLs. Failures retain any completed
creation results, and a retry re-reads existing keys.

A maintainer investigates each issue and fixes the converter or proposes
a blocklist change through a normal PR. This workflow does neither and
does not merge anything.

## Local replay and validation

On Ubuntu 24.04, install CMake/Boost as in the README, plus the pinned
Suricata package. From the repository root:

```sh
sudo apt-get install -y suricata=1:7.0.3-1build3
python3 -m unittest discover -s .github/daily -p 'test_*.py'
cargo test
cargo build --release --example daily
python3 .github/daily/run.py download
target/release/examples/daily convert daily-work daily-results
python3 .github/daily/run.py suricata
target/release/examples/daily compare daily-work daily-results
python3 .github/daily/run.py finish
python3 -c 'import json; raise SystemExit(int(json.load(open("daily-results/status.json"))["failed"]))'
```

Use new work/output directories for a fresh run, or remove prior local
results first. `--work`/`--output` select those directories on the Python
commands; pass the same paths as positional arguments to the Rust tool.
Local `finish` reports an initial baseline unless GitHub workflow
credentials/context are explicitly provided. Local replay never files
issues. The Python test suite uses a fake API for every issue write and
fake downloads for failure tests; the Rust example tests include
accounting, source failures, record extraction, pair/rule classification,
marks, rejected alerts and missing coverage. All are offline.

Release mode keeps vectorscan compilation optimized for full upstream
archives. The standard Rust format, clippy and doc commands in `AGENTS.md` also
apply. `cargo test` includes the example's tests via `test = true`.
`markdownlint-cli2` checks this documentation. Remote PR run URLs and their
actual counts belong in the PR body after the pipeline runs; they cannot
be asserted from a local replay.

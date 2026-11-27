# Daily conversion and differential checks

[The daily workflow](../.github/workflows/daily.yml) runs once daily, on
manual dispatch, and on pull requests changing its implementation or
inputs. A single concurrency group serializes all runs. It is independent
of `ci.yml` and `CI Gate`, and is not a required branch check.
Only a running execution is protected from cancellation: GitHub replaces a
pending run when another enters the group. PR path filters cover the daily
workflow, its tools, dependency manifest and documentation, reducing the
chance of a pending scheduled run being displaced by unrelated library PRs.

The workflow downloads ET Open's Suricata 7.0.3 archive and adjacent
`version.txt`, SigmaHQ's latest `sigma_all_rules.zip` and release
`tag_name`, and the emerging-threats source archive at the last commit
changing that directory. Archives remain in the runner's working directory.
The Rust example consumes local files; the library and Rust tests never
make network requests. Only development dependencies support the example.
GitHub API metadata requests use the job's read-only token to avoid the
shared runner's anonymous API limit. Downloads on other hosts receive no
token, and redirects to another host or scheme strip authentication headers.
Local source downloads optionally use `GH_TOKEN` for the same purpose.

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
`rules-emerging-threats/**`, at the root or inside a sole top-level directory.
Root selection takes precedence; the reader never mixes several wrappers.
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
archive SHA-256 agrees across both stages. Before replay, the Python tool
reads `suricata --dump-config` with the same configuration arguments used
for replay, validates its effective HOME_NET and records those networks for
the Rust comparison to check against its matcher configuration.
Suricata's rules come from the exact archive bytes converted by rulec,
using the same included-file scope. No updater or extra rule source runs.
`--init-errors-fatal` rejects partial signature loading. `-k none` disables
packet checksum validation for offline captures, not protocol inspection.

[The manifest](../.github/daily/pcaps.json) records URLs, SHA-256, provenance,
redistribution terms, and record kind/direction for every pcap. Captures
are checked before replay; a changed digest is never used.

HTTP requests, DNS, SSH, and TLS use existing public captures pinned to a
commit of OISF's `suricata-verify`, under its
[MIT license](https://github.com/OISF/suricata-verify/blob/923478ed7df163c6b126a07e841bc38ecba045d8/LICENSE.txt).
Follow the notice's copyright/permission requirements if redistributing
them. These captures remain temporary downloads, outside artifacts and git.
Their bytes are unmodified. The manifest identifies each capture's protocol
and direction.

### Known deviation: synthetic HTTP response coverage

The issue requires existing public captures and prohibits fixtures made to
fill scopes. HTTP response coverage still uses the Apache-2.0
`protocol-probes.pcap` generated by
[make_probes.py](../.github/daily/make_probes.py). This is an explicit
unfulfilled requirement, not evidence of coverage by real captured traffic.
The existing public captures tested during review produced response alerts
only for rules rejected by the current converter, so removing the probe
would leave the required accepted-response scope empty. Changing converter
support to admit those alerts is outside this workflow's scope.

The fixed probe was originally constructed against the then-current ET
rules: its `curl53` user agent, `example.top` DNS query, `Burp proxy error`
response body, and nested SSH banner deliberately exercise known signature
conditions. Its bytes remain fixed; it is not regenerated to chase later
upstream rule changes. It also contributes request, DNS and SSH traffic;
its observations retain the separate `protocol-probes` pcap identity in
results and issues. The independent public captures above add coverage
from existing traffic. The probe's response observation must be replaced
by a suitable existing public capture to remove this deviation.
CI downloads the probe at the PR head revision; local replay can use its
bundled copy. Neither this probe nor the downloaded captures enter artifacts.

Coverage is measured afresh each run: an accepted ET rule must actually alert in
Suricata in each of these five scopes: HTTP request, HTTP response,
TLS certificate response (`subject.joined`/`issuer.joined`), SSH server
software (`server.software`), and DNS. Checking only the SSH protocol
version does not establish server software coverage. Each scope lists
the observed accepted SIDs and their classifications. A direction-neutral
SSH rule only establishes server
coverage when a Suricata alert is oriented from server to client; a
client-banner alert cannot establish that scope. Similarly, a neutral
HTTP `file.data` rule establishes request or response coverage only when
an alert is observed in that direction. An unknown alert direction
establishes neither side for these neutral rules. A scope with accepted
rules but no observed Suricata alert fails the run. If all source rules
for a scope were rejected, the result's `no_comparable_rules` and run
summary instead report **견줄 규칙 없음** (no comparable rule) with every
rejected SID and its actual conversion reason, without adding a missing scope or
failing the run. Source option names (including legacy
buffer names and HTTP PCRE buffer flags), flow direction, accepted fields,
and rejection IDs from
the same archive determine this distinction anew, without special cases
for a scope or source version. Quoted messages and content are not syntax.
An absent or unrecognized scope without rejected candidates still fails.
Adding pcaps cannot fill a scope whose source rules are all rejected;
converter support must first be addressed in a separate reviewed change.
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
| `method`, `uri` | `http.http_method`, `http.url` |
| `version` | `http.protocol` |
| `host`, `user_agent`, `referer` | Request `Host`, `User-Agent`, `Referer`; `http.hostname`, `http.http_user_agent`, `http.http_refer` are fallbacks when the header list is unavailable |
| `status_code` | `http.status` |
| `response_len` | `http.length` (received response body length), when representable as `usize` |
| `request_len`, `status_msg` | Empty; EVE does not log the received request body length or response reason phrase |
| `username`, `password` | Empty |
| `cookie` | Request `Cookie` |
| `content_encoding`, `content_type`, `cache_control` | Request `Content-Encoding`, `Content-Type`, `Cache-Control`; response headers never fill these fields |
| `filenames`, `mime_types`, `body`, `state` | Empty; EVE does not provide complete body bytes |
| `request_header_names` | `http.request_headers[].name`, preserving case and order |
| `accept`, `connection` | Request `Accept`, `Connection` |
| `accept_encoding`, `accept_language`, `pragma` | Request `Accept-Encoding`, `Accept-Language`, `Pragma` |
| `uri.normalized`, `host.normalized` | Existing rulec normalization of `uri`, `host` |
| `body.request`, `body.response` | Empty, because `body` is empty |
| `header_names.joined`, `header_block` | Existing rulec derivation from request names and the supported request header values above |
<!-- markdownlint-enable MD013 -->

EVE HTTP logging enables `dump-all-headers: both`. Header values come only
from `http.request_headers` and are matched by name ignoring ASCII case.
A complete request header list establishes that an absent header has an
empty value; it is not an extraction limit. A missing list, malformed entry,
or duplicate values that a scalar record cannot preserve remain marked
incomplete, including dependent derived fields. Unknown header values still
follow the library's `header_values_partly_missing` diagnostic.
`Content-Length` is a declared length, not evidence of how many request
body bytes were received; it does not fill `request_len` (chunked, truncated
and incomplete messages would otherwise get invented lengths).

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

If any answer lacks a string `rdata` or an i32-representable TTL, that
array field retains its representable values and is marked incomplete
for input-limit checks. A supplied empty answer array is complete;
an absent array is unavailable.

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
components stay empty. Subject organizational units and other attributes
without a corresponding record field cannot be preserved. A joined name
that omits any such attribute is marked incomplete even when every
representable component is present. These are extraction limits, not
guessed certificate identities.

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
disagreement, or a coverage gap for accepted rules also fail. A scope whose
source rules were all rejected does not fail, with the rejection reasons
reported as described above. The final assertion prints the saved summary
to its job log before checking the exit status, so source errors, excluded
pcaps and coverage gaps are visible in the failed step's logs as well as the run
summary and artifacts. **Disagreement alone
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

# rulec

rulec is the rule compiler for public signature rules: one Rust library
crate that unpacks the ET Open and SigmaHQ rule sets, converts them into
one Sigma-based rule format, compiles them with vectorscan and matches
them against raw events. REview uses it to convert and check rules, and
Hog uses the same crate to compile and match them, so a rule REview
accepts runs the same way in Hog.

## Status

Early development. The crate reads rules in its Sigma-based format,
Clumit Sigma, stores one source's rules as a versioned bundle, compiles
rules with vectorscan and matches events against them through an event
interface. `giganto-client`'s network records (`Conn`, `Dns`, `Http`,
`Tls`, `Ssh`) implement that interface, with derived fields such as a
normalized URI and an unpacked body, and a catalog of their fields lets
a converter check the fields a rule uses. The crate documentation
describes the format, the fields and how values are normalized.

ET Open Suricata 7.0.3 bundles can be converted with `convert_et_open`;
`read_et_open_version` reads their source version without converting or
compiling. Both take archive bytes and an optional external version
number and perform no network access. The conversion applies a supplied
blocklist, checks the field catalog, compiles accepted rules and reports
rejections and compilation statistics. For a local archive:

```sh
cargo run --example et_open_summary -- emerging.rules.tar.gz 11342
```

SigmaHQ release and emerging-threats zip converters are available, with
OS-specific mappings, host field catalogs and version-only inspection.
They accept zip bytes and make no network requests. See the crate
documentation for mapping data, conversion summaries and `!never`
conditions.

Not there yet: event-interface implementations for host records.

## Daily source checks

The independent [daily workflow](docs/daily.md) audits the latest three
source conversions and compares ET Open against Suricata 7.0.3 on public
pcaps. Its documentation covers field provenance, coverage, artifacts,
failure handling, issue filing and local replay.

## Building

The crate builds a vendored copy of vectorscan from source through
[`vectorscan-rs`][vectorscan-rs], so a local build needs CMake, Boost's
headers (1.57 or later) and a C++ compiler besides Rust.

On Ubuntu:

```sh
sudo apt-get update
sudo apt-get install -y build-essential cmake libboost-dev
```

On macOS, with the Xcode Command Line Tools (`xcode-select --install`)
and [Homebrew][homebrew]:

```sh
brew install cmake boost
```

Then build and test as usual:

```sh
cargo build
cargo test
```

## Benchmarks

`benches/throughput.rs` measures compile time, the size of the
vectorscan databases and matching throughput per kind of record:

```sh
cargo bench --bench throughput
```

It compiles 1,000 synthetic rules for each of `conn`, `dns`, `http`,
`tls` and `ssh` and matches synthetic records. To measure a real rule
set against a sample of real records as well, point two environment
variables at them; the measurement on local data runs only when both
are set:

```sh
RULEC_BENCH_RULES=path/to/rules RULEC_BENCH_RECORDS=path/to/records \
    cargo bench --bench throughput
```

- `RULEC_BENCH_RULES` is a directory of Clumit Sigma files (`.yml` or
  `.yaml`), or one rule bundle file as `RuleBundle::to_bytes` writes it.
- `RULEC_BENCH_RECORDS` is a directory holding `conn.jsonl`,
  `dns.jsonl`, `http.jsonl`, `ssh.jsonl` and `tls.jsonl`; a missing file
  is skipped. Each line is one `giganto-client` record of that kind
  written with `serde_json`, such as this line of `conn.jsonl`:

  ```json
  {"orig_addr":"10.0.0.1","orig_port":49152,"resp_addr":"192.0.2.10","resp_port":80,"proto":6,"conn_state":"SF","start_time":1700000000000000000,"duration":1500000000,"service":"http","orig_bytes":512,"resp_bytes":2048,"orig_pkts":6,"resp_pkts":5,"orig_l2_bytes":900,"resp_l2_bytes":2500}
  ```

  `Http::body` is written as an array of byte values.

## License

Copyright 2026 ClumL Inc.

Licensed under [Apache License, Version 2.0][apache-license] (the "License");
you may not use this crate except in compliance with the License.

Unless required by applicable law or agreed to in writing, software distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied. See [LICENSE](LICENSE) for
the specific language governing permissions and limitations under the License.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the [Apache-2.0
license][apache-license], shall be licensed as above, without any additional
terms or conditions.

[apache-license]: http://www.apache.org/licenses/LICENSE-2.0
[homebrew]: https://brew.sh
[vectorscan-rs]: https://crates.io/crates/vectorscan-rs

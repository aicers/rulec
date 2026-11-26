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
interface. The crate documentation describes the format.

Not there yet: reading fields out of `giganto-client` records into that
interface, and the converters from ET Open and SigmaHQ.

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

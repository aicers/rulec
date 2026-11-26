# rulec

rulec is the rule compiler for public signature rules. It is planned as
one Rust crate that unpacks the ET Open and SigmaHQ rule sets, converts
them into one Sigma-based rule format, compiles them with vectorscan and
matches them against raw events. REview uses it to convert and check
rules, and Hog uses the same crate to compile and match them, so a rule
REview accepts runs the same way in Hog.

## Status

Early concept. This repository does not contain any code yet.

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

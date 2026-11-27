# Changelog

This file documents recent notable changes to this project. The format of this
file is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0](https://github.com/aicers/rulec/releases/tag/0.1.0) - 2026-11-27

### Added

- convert SigmaHQ rule sets ([#22](https://github.com/aicers/rulec/pull/22))
- convert ET Open rule bundles ([#23](https://github.com/aicers/rulec/pull/23))
- read fields out of giganto-client network records ([#17](https://github.com/aicers/rulec/pull/17))
- add the Clumit Sigma rule format, rule bundles, compilation and matching ([#13](https://github.com/aicers/rulec/pull/13))
- add the rulec crate with vectorscan and giganto-client dependencies ([#11](https://github.com/aicers/rulec/pull/11))

### Fixed

- stop dechunking at the output cap ([#21](https://github.com/aicers/rulec/pull/21))
- match ? one byte at a time where no well-formed UTF-8 character starts ([#18](https://github.com/aicers/rulec/pull/18))

### Other

- document the modifier combinations and the per-value expansion limit ([#16](https://github.com/aicers/rulec/pull/16))
- update shared instruction blocks to 0.6.5 ([#3](https://github.com/aicers/rulec/pull/3))
- add shared agent instructions and release-plz automation ([#2](https://github.com/aicers/rulec/pull/2))
- Initial commit

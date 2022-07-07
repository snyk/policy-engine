# CHANGELOG



## v0.1.1 - 2022-07-07
### Fixed
* resource ID scrambling bug in annotation step
* input was not being set in repl

## v0.1.0 - 2022-07-05
### Added
* allow tests to be filtered by name
* Proposal for `snyk.matches_snapshot()` builtin
* Support for legacy IaC rules
* VarFiles option
* Engine performance improvements and configurable rule evaluation workers
* snapshot_testing.match builtin function
### Changed
* `pkg/loader` to `pkg/input`
### Removed
* Removed http.send from Rego API
### Fixed
* errors from builtins not being raised
* Missing resource_namespace from fugue rules
* Avoid overlapping resource IDs in tfstate loader
* Correct file path for loaded Rego files
* Allow array JSON files in data directories
### Security
* Propagate afero.Fs into Terraform functions

## v0.0.3 - 2022-06-22
### Fixed
* links in query / ResourcesResolver docs
* crash when no ResourcesResolvers configured
* Premature exits in commands

## v0.0.2 - 2022-06-22
### Fixed
* links in query / ResourcesResolver docs
* crash when no ResourcesResolvers configured

## v0.0.1 - 2022-06-21
### Added
* Initial release
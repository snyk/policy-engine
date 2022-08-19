# CHANGELOG



## v0.6.0 - 2022-08-19
### Added
* k8s manifest loader
* support for legacy k8s rules
* populate tfplan.resource_actions metadata
* postprocess.ResourceFilter
* Support for quotes in legacy IaC msg parser
* support json-formatted k8s manifests
* Type() method to input.IACConfiguration
* Equal() method to input.Type
### Changed
* always include _meta in resources
* refactored cfn loader to remove toState() use
* moved input.AnnotateResults to postprocess.AddSourceLocs
* skip invalid k8s objects rather than failing
### Removed
* toState transformation from regula
### Fixed
* CLOUD-656 derive input_type for legacy iac rules
* Fix resource ID collision with namespaces in k8s

## v0.5.0 - 2022-08-12
### Added
* set meta.provider_config in tf and tfplan loaders
* update metadata schema to have references in structured format
* Filepath to tfPlan.Location()
### Changed
* Disabled strict builtins for legacy IaC rules
### Fixed
* Populated rule result description with legacy rule impact instead of rule issue
* Empty resources not being output by CFN parser
* fix panic for outputs without expressions
* panic on marked `cty.Value`

## v0.4.0 - 2022-08-01
### Added
* docs: clarify empty array result from snyk.resources
* Accumulate errors in TF loader instead of printing warnings.  They are available under `loader.Errors()`
### Changed
* Default behavior for `input_type`. After this change, policies that do not define an `input_type` rule will be evaluated for all input types.
### Fixed
* docs: update example for array result of snyk.resources() 
* sync models code and swagger
* Compatibility issues with legacy IaC rules (see #82 for more information)
* ARM parser to capture all resource attributes
* Missing severity and remediation on "missing resource" policy results
* panic from using both Terraform and policy-engine as librarires (see fugue/regula#350)
### Security
* Updated OPA to v0.43.0

## v0.3.0 - 2022-07-12
### Added
* -i flag for repl to run commands on initialization
* Infer primary resource if there's only one
### Fixed
* panic on retrieving key from nil resource

## v0.2.0 - 2022-07-11
### Added
* `policy-engine version` subcommand
* Add consistency check when writing multiple files using --update-snapshots
* Configurable mock query() implementation for tests
### Changed
* `snapshot_testing.match` files are written with a trailing newline
* cfn loader: embed schemas and coerce values to expected types

## v0.1.2 - 2022-07-08
### Fixed
* enable tracing in test command when -v is given
* ensure passing tests can't set exit code back to 0
* panic when using tfplan on resources with count

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
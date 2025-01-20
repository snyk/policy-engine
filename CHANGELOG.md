# CHANGELOG



## v0.33.0 - 2025-01-20
### Added
* upgrade for open-policy-agent v0.69.0

## v0.32.1 - 2024-12-13
### Fixed
* upgrade go to v1.20 and crypto lib

## v0.32.0 - 2024-12-03
### Added
* support for a user-defined free form output for the single-resource and multi-resource policy types
### Fixed
* added gitleaks ignore for false positive

## v0.31.3 - 2024-09-10
### Fixed
* upgrade go-getter package to v1.7.5

## v0.31.2 - 2024-07-25
### Fixed
* adding new security quality gates
* fix location computation for resources with multi-char ID inside square brackets

## v0.31.1 - 2024-06-25
### Fixed
* upgrade go-retryablehttp to v0.7.7

## v0.31.0 - 2024-05-14
### Fixed
* update ownership to iac

## v0.30.11 - 2024-04-19
### Fixed
* increase default timeouts - for query and init
* address http2 and go-getter vuln

## v0.30.10 - 2024-04-02
### Fixed
* increase default timeouts - for query and init

## v0.30.9 - 2024-04-01
### Fixed
* Filtering tfplan references to properly consider counts

## v0.30.8 - 2024-03-22
### Fixed
* panic in forEachResult.add

## v0.30.7 - 2024-03-20
### Fixed
* do not panic on invalid arm input

## v0.30.6 - 2024-01-12
### Fixed
* `capnslog` is not imported anymore, removing a logging-sideffect

## v0.30.5 - 2023-11-23
### Fixed
* phantom attributes on multi-resources

## v0.30.4 - 2023-11-16
### Fixed
* Stop masking empty sensitive attributes. This can make unset attributes, which appear as empty string rather than null in some terraform plans, appear as if they are set.

## v0.30.3 - 2023-10-11
### Fixed
* count and for_each appearing in attributes
* upgraded http2 and google-storage and grpc to remove DoS vulns

## v0.30.2 - 2023-09-29
### Added
* add catalog-info.yaml for asset classification
### Fixed
* source locations for count/for_each resources in tf loader
* fix: resource schema mixup when count/for_each fails to evaluate

## v0.30.1 - 2023-09-08
### Changed
* store resources with a for_each as objects rather than tuples
### Fixed
* remove spurious warning for static missing terms

## v0.30.0 - 2023-09-06
### Added
* Support for Terraform path.root and path.cwd
### Changed
* tweak error message for EvaluationError in hcl_interpreter
* Documentation around kubernetes key in remediation object 
### Fixed
* non-string variables defaulting to string instead of null
* issue parsing remote terraform module register
* add source code location to missing term errors
* remove spurious warnings for default iterator
* Remediation advice is emitted for every resource type
### Updated
* clarify that custom metadata fields are ignored

## v0.29.1 - 2023-08-21
### Fixed
* Panic when parsing non-string CFN tags

## v0.29.0 - 2023-08-17
### Added
* cache resource queries
### Changed
* BREAKING: EvalOptions now takes a ResourcesQueryCache instead of a ResourcesResolver
### Fixed
* ensure `snyk.resources()` are returned in a deterministic order
### Updated
* remove __resources_by_type builtin
* refactor unmarshalling of resources query

## v0.28.0 - 2023-08-14
### Added
* capabilities subcommand
* upload extra files to github releases
### Fixed
* Don't snyk-monitor on build
### Security
* Snyk code and dependency scanning

## v0.27.0 - 2023-07-25
### Added
* evaluate ARM template expressions during resource discovery (CLOUD-1648)
### Security
* Secrets scan in CICD and pre-commit hook

## v0.26.0 - 2023-06-29
### Added
* Initial support for evaluating ARM template expressions
* Initial support for ARM template variables
* Add support for a few ARM template string functions
### Changed
* refactor: arm EvaluationContext

## v0.25.0 - 2023-06-23
### Added
* `policy-engine run` will now search for IaC configurations recursively if passed a directory
### Changed
* `input.Loader` detects and avoids duplicate file loads


## v0.24.3 - 2023-06-13
### Fixed
* make ARM tag parsing errors non-fatal

## v0.24.2 - 2023-06-01
### Added
* cache resource relations in between policies in the same bundle

## v0.24.1 - 2023-05-31
### Added
* normalize resource tags and expose them as _tags to policies
### Changed
* informational severity to info
### Fixed
* missing rule result fields when unmarshalled

## v0.24.0 - 2023-05-26
### Added
* allow annotations on resource relations
* `kind` and `graph` fields to policies
### Fixed
* typos in relation annotation docs
* small bug in license script

## v0.23.0 - 2023-05-23
### Added
* Configurable timeouts to the engine package
* support for dynamic blocks in terraform loader

## v0.22.0 - 2023-05-11
### Added
* sentiel errors for non-fatal errors
* expose the embedded version info for terraform
* Added a new sentinel error when we recieve an error when loading a submodule
* expose repl as a library
### Changed
* use allowlist rather than denylist for OPA builtins
### Fixed
* rules without messages produce messages containing '\n\n' when they produce multiple results
* set capabilities in REPL

## v0.21.1 - 2023-04-26
### Fixed
* deny parsing for key-less rules
* bug where paths, e.g. /api, were dropped from cloudapi.ClientConfig.URL

## v0.21.0 - 2023-04-25
### Added
* Engine.Query() method to support arbitrary queries
* alternate method to configure authorization for cloudapi.Client
* add name to bundle manifest
* pkg/test to easily run rego tests
### Changed
* Switch to using opa/topdown rather than opa/rego

## v0.20.0 - 2023-04-18
### Added
* cloud resources options to repl command
* docs around security aspects
* snyk.relation_from_fields helper function for writing relations rules
### Fixed
* missing denied resources in one case for fugue rules

## v0.19.0 - 2023-03-16
### Added
* explicit --log-level flag
* --input-type flag for fixture command
* support for cloud resources in run, fixture, and eval commands
### Fixed
* complete bundle example
* bug where HCL syntax errors were being treated as non-fatal
### Updated
* .snyk MPL 2.0 ignores
* Copyright headers

## v0.18.3 - 2023-02-20
### Changed
* upgrade go-getter to v1.7.0
* upgrade net to v0.7.0

## v0.18.2 - 2023-02-17
### Changed
* disabled logging by default

## v0.18.1 - 2023-02-15
### Fixed
* panic on null for_each value

## v0.18.0 - 2023-02-14
### Updated
* vendored Terraform to v1.3.8
* license and copyright blocks

## v0.17.0 - 2023-02-10
### Added
* API for evaluating bundles
* bundle create, validate, and show commands
### Changed
* updated release docs
### Fixed
* fix panic using unset vars in locals

## v0.16.1 - 2023-02-09

### Changed
* improve release process
### Fixed
* broken multi-resource policies that reference input for testing purposes


## v0.16.0 - 2023-02-07
### Added
* add `eval` command for use in scripts
* Policy bundle specification document
### Fixed
* remove input for multi-resource policies to address extreme memory usage for large inputs

## v0.15.0 - 2023-01-23
### Added
* for_each support
* count will create multiple resources rather than creating a template resource
### Changed
* return more resource metadata from the hcl_interpreter library
* revert ReadCloser change to targz provider
* updated resource relations naming conventions to use resource_type.attribute_name

## v0.14.1 - 2023-01-10
### Added
* document release process
* support -v in fixture command
### Fixed
* too many open files when reading large amount of rego files

## v0.14.0 - 2022-12-19
### Changed
* adopt new metadata format for compliance mappings
### Fixed
* Return non-zero exit code on error

## v0.13.0 - 2022-12-13
### Added
* resource relationships
### Fixed
* return empty arrays from snyk.(back_)relates if nothing found
* respect -v flag in test reporter

## v0.12.2 - 2022-11-15
### Added
* support for unset attributes and single-term expressions to attribute tracer

## v0.12.1 - 2022-11-03
### Fixed
* mismatch between resource_id in rule results and Resource.ID

## v0.12.0 - 2022-10-26
### Added
* infer resource attributes automatically if not present

## v0.11.0 - 2022-10-20
### Added
* use terraform schemas to scrub sensitive fields in tf and tfplan loaders
* use terraform schemas to coerce values to expected types in tf and tfplan loaders
### Fixed
* Enable `print()` statements in the `test` command
* Use the configured Engine logger when evaluating policies
* Return a FailedToParseInput error if an HCL evaluation fails

## v0.10.0 - 2022-10-04
### Added
* _id attribute that always contains logical ID and retain physical ID when defined in the id attribute
### Changed
* ensure all arrays in output are deterministically sorted

## v0.9.0 - 2022-09-29
### Added
* proposal to add result_tag to policy result identity
* new `product` metadata field
* support for .tf.json Terraform source code files
### Fixed
* Primary resource interpretation for missing-resource policies
* resource .id in repl/test
* duplicate resource IDs in tfstate
### Security
* Bump OPA to v0.44.0

## v0.8.0 - 2022-09-19
### Added
* Rego API support for secondary resource denies
* postprocess.ApplyCustomSeverities
### Changed
* BREAKING: move ResourcesResolver chain to eval time

## v0.7.0 - 2022-09-02
### Added
* Apache V2 licensing
* contributor guidelines
* Proposal for enhancement to deny rules for secondary resources
* method to extract all policy metadata
### Changed
* use license notice rather than full text in LICENSE
* Convert legacy iac k8s messages to OPA style paths
* Documentation for policies
### Removed
* markdown-style references in metadata
* deprecated `tf_runtime` / `streamlined_state` input type
### Fixed
* support data resources in tfplan and tfstate loaders
* LICENSE formatting

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
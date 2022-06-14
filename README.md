# Unified Policy Engine

This repository contains a Go library that performs two main functions:

* Parses IaC configurations
* Evaluates resources using Open Policy Agent

It also provides a small CLI that can be used to author and test policies.

```sh
go build
./policy-engine help
```

## Additional documentation

Additional documentation can be found in the [`docs`](./docs) directory. The current
set of additional documents are:

* [Policies specification](docs/policy_spec.md)
  * Describes the structure and API for writing policies
* [Policy authoring guide](docs/policy_authoring.md)
  * Contains a tutorial for authoring policies and instructions for writing policy tests
* [Use as a library](docs/library_usage.md)
  * Describes how to use `policy-engine` as a Go library

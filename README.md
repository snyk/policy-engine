# Policy Engine

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
* [Notes for policy engine developers](docs/development.md)
  * Describes processes and conventions for working on this repository
* [Security](docs/security.md)
  * Describes measures to take when policy-engine on untrusted inputs or code

## Contributing

Should you wish to make a contribution please open a pull request against this
repository with a clear description of the change with tests demonstrating
the functionality. You will also need to agree to the [Contributor
Agreement](./Contributor-Agreement.md) before the code can be accepted and
merged.

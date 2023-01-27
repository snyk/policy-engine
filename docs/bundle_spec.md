# Policy bundle specification

This document describes the contract and API for policy bundles that run in the policy engine.

- [Policy bundle specification](#policy-bundle-specification)
  - [Policy bundle requirements](#policy-bundle-requirements)
    - [`manifest.json`](#manifestjson)
      - [Fields](#fields)
  - [Optional bundle contents](#optional-bundle-contents)
    - [`lib` directory](#lib-directory)
      - [Restrictions](#restrictions)
  - [Examples](#examples)
    - [Example bundle directory structure](#example-bundle-directory-structure)
    - [Example `manifest.json`](#example-manifestjson)

## Policy bundle requirements

1. Policy bundles must be a GZipped Tar file
2. Policy bundles must contain a [`manifest.json`](#manifestjson) file with the required fields
3. Policy bundles must contain one or more policies that meet the requirements defined in the
   [Policies specification](policy_spec.md)
4. Policies must be stored within a top-level `rules` directory

### `manifest.json`

A `manifest.json` file in the root of the bundle will be interpreted as "bundle metadata". This
metadata contains identifying information about the policy bundle.

#### Fields

| Field                   |  Type  | Required | Description                                                                  |
| :---------------------- | :----: | :------: | :--------------------------------------------------------------------------- |
| `bundle_format_version` | string |   yes    | The version of policy engine bundle format that this bundle conforms to      |
| `policy_engine_version` | string |    no    | The version of policy engine used to develop or build this bundle            |
| `revision`              | string |    no    | The revision of the bundle, e.g. a Git hash                                  |
| `vcs`                   | object |    no    | Version control system (VCS) information                                     |
| `vcs.type`              | string |    no    | The type of VCS used, e.g. git, mercurial, svn                               |
| `vcs.uri`               | string |    no    | A URI to the source of this bundle, e.g. https://github.com/example/policies |

## Optional bundle contents

### `lib` directory

Non-rule code, like shared libraries, can be included in a top-level `lib` directory.

#### Restrictions

Both the `lib/snyk` directory and the `lib.snyk` Rego package are reserved for Snyk-provided
libraries and may be overwritten by Snyk tooling.

## Examples

### Example bundle directory structure

```
.
├── lib
│   └── utils.rego
├── manifest.json
└── rules
    ├── EXAMPLE-01
    │   └── terraform.rego
    ├── EXAMPLE-02
    │   └── terraform.rego
    └── EXAMPLE-03
        └── terraform.rego
```

### Example `manifest.json`

```json
{
    "bundle_format_version": "v0.0.1",
    "policy_engine_version": "v0.15.0",
    "revision": "22e2f3bccb6fd28733bfbf445ba41e26e0fc32af",
    "vcs": {
        "type": "git",
        "uri": "git@github.com:example/rules.git"
    }
}
```

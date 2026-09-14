# AGENTS.md

Guidance for AI coding agents working in this repository. Read this before making any changes.

`policy-engine` is a Go library and CLI that parses IaC configuration (Terraform, CloudFormation, etc. — see `pkg/input`) and evaluates it against [Open Policy Agent](https://www.openpolicyagent.org/) (Rego) policies. It's designed to be used as a Go library (see `docs/library_usage.md`) as well as run as a standalone CLI for authoring and testing policies locally. It's open source — see `LICENSE` and `Contributor-Agreement.md` — so external contributors can and do open PRs here.

## Architecture

`main.go` is a thin wrapper around the Cobra command tree in `cmd/` (`run`, `eval`, `test`, `bundle *`, `repl`, `fixture`, `capabilities`, `metadata`, `version`). The engine itself lives under `pkg/`:

| Directory | Purpose |
|---|---|
| `pkg/input` | Parsers for IaC formats (e.g. Terraform HCL) into the engine's internal resource model |
| `pkg/hcl_interpreter` | HCL evaluation support used by the Terraform parser |
| `pkg/engine` | Core evaluation engine: runs Rego policies against parsed input |
| `pkg/policy` | Policy loading/metadata |
| `pkg/bundle` | OPA bundle handling (`bundle create/show/validate`) |
| `pkg/data` | Data document handling for policy evaluation |
| `pkg/postprocess` | Result post-processing |
| `pkg/rego` | Go-side Rego integration (builtins, evaluator plumbing) |
| `pkg/snapshot_testing` | Snapshot-test harness used by policy/engine tests |
| `pkg/topsort` | Topological sort helper |
| `pkg/logging`, `pkg/metrics` | Structured logging and metrics |
| `pkg/version` | Version string, injected via `-ldflags` at build time (see `Makefile`) |
| `rego/` | A **pure-Rego** reimplementation of engine functionality, for testing and REPL-based development only — not used for production evaluation (see `rego/README.md`) |
| `examples/` | Sample Terraform + policies used by `make demo` and referenced in the docs |
| `docs/` | Policy spec, policy-authoring guide, library-usage guide, release process, security notes |

## Generated / vendored code — do not hand-edit

| Path | Source | Regenerate with |
|---|---|---|
| `pkg/models/model_*.go` | swagger-codegen from `swagger.yaml` | `make swagger` (requires Docker) |
| `pkg/internal/terraform/` | Vendored from `hashicorp/terraform` internal packages, then patched | `make vendor_terraform` (applies `patches/terraform.patch` after copying) |
| `CHANGELOG.md` | Batched from `changes/*.yaml` fragments by `changie` | Don't hand-edit — add a new fragment (`changie new`) and let `make release` batch it |

If a fix is needed inside `pkg/internal/terraform/`, edit `patches/terraform.patch` and re-run `make vendor_terraform` — a direct edit gets silently overwritten the next time someone re-vendors.

## Building and testing

```sh
go build          # builds ./policy-engine
make demo         # builds, then runs the CLI against examples/ to sanity-check evaluation
```

Tests are **two separate commands**, both required (see [`.github/workflows/test.yaml`](.github/workflows/test.yaml), which runs them against Go 1.24.12 and 1.25.6):

```sh
go test ./...
opa test rego     # requires the OPA CLI: go install github.com/open-policy-agent/opa@v0.69.0 (version must match go.mod)
```

This repo also has a **git submodule** (`pkg/input/golden_test/tf/example-terraform-modules`). Clone with `--recurse-submodules`, or run `git submodule update --init` after the fact — otherwise Terraform-parser golden tests fail with missing-fixture errors that look unrelated to your change.

There's a `.pre-commit-config.yaml` — run `pre-commit install` once rather than relying on CI to catch formatting first.

## Releasing

Releases are automated — see [`docs/development.md`](docs/development.md) for the full process; don't improvise a manual one. In short: `VERSION=v1.2.3 make release` batches `changes/` fragments into `CHANGELOG.md` and opens a `release/*` branch; merging that to `main` triggers [`release_workflow.yml`](.github/workflows/release_workflow.yml) (tag + `goreleaser` build/publish). Add a changie fragment (`changie new`) on any user-facing PR so it lands in the next release's changelog.

## Conventions

- New CLI subcommands go in `cmd/`, following the existing Cobra pattern in `cmd/root.go`; give them a `docs/` entry if they're user-facing.
- Keep `pkg/rego` (Go-side integration) and the top-level `rego/` (pure-Rego, test-only) in sync when changing evaluation semantics — `rego/README.md` explains why both exist.
- The OPA version is pinned in two places that must move together: the `github.com/open-policy-agent/opa` entry in `go.mod` and the `opa` version installed in `.github/workflows/test.yaml`.
- Commit style seen on `main`: `<type>: <lowercase description> [TICKET-ID]` (e.g. `fix: bump go version [IAC-3502]`), squash-merged so GitHub appends `(#NNN)` — don't type the PR number yourself.

## Before you finish

- [ ] `go test ./...` passes
- [ ] `opa test rego` passes if you touched anything under `rego/` or policy evaluation semantics
- [ ] `make demo` still runs cleanly if you touched `pkg/engine`, `pkg/input`, or `cmd/run.go`
- [ ] A changie fragment was added under `changes/` for user-facing changes
- [ ] `pkg/models/*.go` and `pkg/internal/terraform/*.go` are untouched by hand
- [ ] `.pre-commit-config.yaml` hooks pass

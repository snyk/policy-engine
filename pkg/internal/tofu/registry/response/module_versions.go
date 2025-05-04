// Copyright (c) The OpenTofu Authors
// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2023 HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package response

// ModuleVersions is the response format that contains all metadata about module
// versions needed for tofu CLI to resolve version constraints. See RFC
// TF-042 for details on this format.
type ModuleVersions struct {
	Modules []*ModuleProviderVersions `json:"modules"`
}

// ModuleProviderVersions is the response format for a single module instance,
// containing metadata about all versions and their dependencies.
type ModuleProviderVersions struct {
	Source   string           `json:"source"`
	Versions []*ModuleVersion `json:"versions"`
}

// ModuleVersion is the output metadata for a given version needed by CLI to
// resolve candidate versions to satisfy requirements.
type ModuleVersion struct {
	Version    string              `json:"version"`
	Root       VersionSubmodule    `json:"root"`
	Submodules []*VersionSubmodule `json:"submodules"`
}

// VersionSubmodule is the output metadata for a submodule within a given
// version needed by CLI to resolve candidate versions to satisfy requirements.
// When representing the Root in JSON the path is omitted.
type VersionSubmodule struct {
	Path         string               `json:"path,omitempty"`
	Providers    []*ModuleProviderDep `json:"providers"`
	Dependencies []*ModuleDep         `json:"dependencies"`
}

// Copyright (c) The OpenTofu Authors
// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2023 HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package tofu

import "github.com/opentofu/opentofu/internal/addrs"

// nodeExternalReference allows external callers (such as the testing framework)
// to provide the list of references they are making into the graph. This
// ensures that OpenTofu will not remove any nodes from the graph that might
// not be referenced from within a module but are referenced by the currently
// executing test file.
//
// This should only be added to the graph if we are executing the
// `tofu test` command.
type nodeExternalReference struct {
	ExternalReferences []*addrs.Reference
}

var (
	_ GraphNodeReferencer = (*nodeExternalReference)(nil)
)

// GraphNodeModulePath
func (n *nodeExternalReference) ModulePath() addrs.Module {
	// The external references are always made from test files, which currently
	// execute as if they are in the root module.
	return addrs.RootModule
}

// GraphNodeReferencer
func (n *nodeExternalReference) References() []*addrs.Reference {
	return n.ExternalReferences
}

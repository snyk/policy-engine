// Copyright (c) The OpenTofu Authors
// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2023 HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	localexec "github.com/snyk/policy-engine/pkg/internal/tofu/builtin/provisioners/local-exec"
	"github.com/snyk/policy-engine/pkg/internal/tofu/grpcwrap"
	"github.com/snyk/policy-engine/pkg/internal/tofu/plugin"
	"github.com/snyk/policy-engine/pkg/internal/tofu/tfplugin5"
)

func main() {
	// Provide a binary version of the internal terraform provider for testing
	plugin.Serve(&plugin.ServeOpts{
		GRPCProvisionerFunc: func() tfplugin5.ProvisionerServer {
			return grpcwrap.Provisioner(localexec.New())
		},
	})
}

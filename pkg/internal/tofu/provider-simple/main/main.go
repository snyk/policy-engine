// Copyright (c) The OpenTofu Authors
// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2023 HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"github.com/snyk/policy-engine/pkg/internal/tofu/grpcwrap"
	"github.com/snyk/policy-engine/pkg/internal/tofu/plugin"
	simple "github.com/snyk/policy-engine/pkg/internal/tofu/provider-simple"
	"github.com/snyk/policy-engine/pkg/internal/tofu/tfplugin5"
)

func main() {
	plugin.Serve(&plugin.ServeOpts{
		GRPCProviderFunc: func() tfplugin5.ProviderServer {
			return grpcwrap.Provider(simple.Provider())
		},
	})
}

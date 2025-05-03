// Copyright (c) The OpenTofu Authors
// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2023 HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"github.com/snyk/policy-engine/pkg/internal/tofu/grpcwrap"
	plugin "github.com/snyk/policy-engine/pkg/internal/tofu/plugin6"
	simple "github.com/snyk/policy-engine/pkg/internal/tofu/provider-simple-v6"
	"github.com/snyk/policy-engine/pkg/internal/tofu/tfplugin6"
)

func main() {
	plugin.Serve(&plugin.ServeOpts{
		GRPCProviderFunc: func() tfplugin6.ProviderServer {
			return grpcwrap.Provider6(simple.Provider())
		},
	})
}

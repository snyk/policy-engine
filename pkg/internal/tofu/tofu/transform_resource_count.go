// Copyright (c) The OpenTofu Authors
// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2023 HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package tofu

import (
	"log"

	"github.com/snyk/policy-engine/pkg/internal/tofu/addrs"
	"github.com/snyk/policy-engine/pkg/internal/tofu/configs/configschema"
	"github.com/snyk/policy-engine/pkg/internal/tofu/dag"
)

// ResourceCountTransformer is a GraphTransformer that expands the count
// out for a specific resource.
//
// This assumes that the count is already interpolated.
type ResourceCountTransformer struct {
	Concrete ConcreteResourceInstanceNodeFunc
	Schema   *configschema.Block

	Addr          addrs.ConfigResource
	InstanceAddrs []addrs.AbsResourceInstance
}

func (t *ResourceCountTransformer) Transform(g *Graph) error {
	for _, addr := range t.InstanceAddrs {
		abstract := NewNodeAbstractResourceInstance(addr)
		abstract.Schema = t.Schema
		var node dag.Vertex = abstract
		if f := t.Concrete; f != nil {
			node = f(abstract)
		}

		log.Printf("[TRACE] ResourceCountTransformer: adding %s as %T", addr, node)
		g.Add(node)
	}
	return nil
}

package terraform

import (
	"github.com/snyk/policy-engine/pkg/internal/terraform/addrs"
	"github.com/snyk/policy-engine/pkg/internal/terraform/configs"
)

// RootVariableTransformer is a GraphTransformer that adds all the root
// variables to the graph.
//
// Root variables are currently no-ops but they must be added to the
// graph since downstream things that depend on them must be able to
// reach them.
type RootVariableTransformer struct {
	Config *configs.Config

	RawValues InputValues
}

func (t *RootVariableTransformer) Transform(g *Graph) error {
	// We can have no variables if we have no config.
	if t.Config == nil {
		return nil
	}

	// We're only considering root module variables here, since child
	// module variables are handled by ModuleVariableTransformer.
	vars := t.Config.Module.Variables

	// Add all variables here
	for _, v := range vars {
		node := &NodeRootVariable{
			Addr: addrs.InputVariable{
				Name: v.Name,
			},
			Config:   v,
			RawValue: t.RawValues[v.Name],
		}
		g.Add(node)
	}

	return nil
}

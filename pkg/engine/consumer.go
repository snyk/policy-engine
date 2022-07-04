package engine

import (
	"context"

	"github.com/open-policy-agent/opa/ast"
	"github.com/snyk/policy-engine/pkg/interfacetricks"
)

var rulesPrefix = ast.Ref{
	ast.DefaultRootDocument,
	ast.StringTerm("rules"),
}

// PolicyConsumer is an implementation of the data.Consumer interface that stores
// parsed modules, policies, and documents in-memory.
type PolicyConsumer struct {
	Modules      map[string]*ast.Module
	Document     map[string]interface{}
	NumDocuments int
}

func NewPolicyConsumer() *PolicyConsumer {
	return &PolicyConsumer{
		Modules:      map[string]*ast.Module{},
		Document:     map[string]interface{}{},
		NumDocuments: 0,
	}
}

func (c *PolicyConsumer) Module(
	ctx context.Context,
	path string,
	module *ast.Module,
) error {
	c.Modules[path] = module
	return nil
}

func (c *PolicyConsumer) DataDocument(
	_ context.Context,
	path string,
	document map[string]interface{},
) error {
	c.Document = interfacetricks.MergeObjects(c.Document, document)
	c.NumDocuments += 1
	return nil
}

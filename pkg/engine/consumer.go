package engine

import (
	"context"
	"path/filepath"
	"strings"

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
	Modules   map[string]*ast.Module
	Documents map[string]interface{}
}

func NewPolicyConsumer() *PolicyConsumer {
	return &PolicyConsumer{
		Modules:   map[string]*ast.Module{},
		Documents: map[string]interface{}{},
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
	prefix := dataDocumentPrefix(path)
	for i := len(prefix) - 1; i >= 0; i-- {
		document = map[string]interface{}{
			prefix[i]: document,
		}
	}
	c.Documents = interfacetricks.MergeObjects(c.Documents, document)
	return nil
}

// Returns a prefix to nest the document under based on the filename.  This
// matches the OPA behaviour.
//
//     metadata/rules/snyk_001/metadata.json
//
// Results in
//
//     ["rules", "snyk_001"]
func dataDocumentPrefix(path string) []string {
	prefix := []string{}
	for _, part := range strings.Split(filepath.ToSlash(filepath.Dir(path)), "/") {
		if part != "" {
			prefix = append(prefix, part)
		}
	}
	return prefix
}

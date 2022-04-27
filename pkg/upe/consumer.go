package upe

import (
	"context"
	"path/filepath"
	"strings"

	"github.com/open-policy-agent/opa/ast"
	"github.com/snyk/unified-policy-engine/pkg/interfacetricks"
	"github.com/snyk/unified-policy-engine/pkg/logging"
	"github.com/snyk/unified-policy-engine/pkg/policy"
)

var rulesPrefix = ast.Ref{
	ast.DefaultRootDocument,
	ast.StringTerm("rules"),
}

// PolicyConsumer is an implementation of the data.Consumer interface that stores
// parsed modules, policies, and documents in-memory.
type PolicyConsumer struct {
	Policies  []policy.Policy
	Modules   map[string]*ast.Module
	Documents map[string]interface{}
	logger    logging.Logger
}

func NewPolicyConsumer(logger logging.Logger) *PolicyConsumer {
	return &PolicyConsumer{
		Modules:   map[string]*ast.Module{},
		Documents: map[string]interface{}{},
		logger:    logger,
	}
}

func (c *PolicyConsumer) Module(
	ctx context.Context,
	path string,
	module *ast.Module,
) error {
	c.Modules[path] = module
	if module.Package.Path.HasPrefix(rulesPrefix) {
		p, err := policy.PolicyFactory(module)
		if err != nil {
			c.logger.
				WithField(logging.PATH, path).
				WithField(logging.ERROR, err.Error()).
				Debug(ctx, "Unable to parse as a policy")
			return nil
		} else {
			c.Policies = append(c.Policies, p)
		}

	}
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

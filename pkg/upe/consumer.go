package upe

import (
	"path/filepath"
	"strings"

	"github.com/open-policy-agent/opa/ast"
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
}

func NewPolicyConsumer() *PolicyConsumer {
	return &PolicyConsumer{
		Modules:   map[string]*ast.Module{},
		Documents: map[string]interface{}{},
	}
}

func (c *PolicyConsumer) Module(path string, module *ast.Module) error {
	c.Modules[path] = module
	if module.Package.Path.HasPrefix(rulesPrefix) {
		p, err := policy.PolicyFactory(module)
		if err != nil {
			return err
		} else {
			c.Policies = append(c.Policies, p)
		}

	}
	return nil
}

func (c *PolicyConsumer) DataDocument(path string, document map[string]interface{}) error {
	prefix := dataDocumentPrefix(path)
	for i := len(prefix) - 1; i >= 0; i-- {
		document = map[string]interface{}{
			prefix[i]: document,
		}
	}
	c.Documents = mergeObjects(c.Documents, document)
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

func mergeObjects(left map[string]interface{}, right map[string]interface{}) map[string]interface{} {
	for k, rv := range right {
		if lv, ok := left[k]; ok {
			mergeDocuments(lv, rv)
		} else {
			left[k] = rv
		}
	}
	return left
}

func mergeDocuments(left interface{}, right interface{}) interface{} {
	switch l := left.(type) {
	case map[string]interface{}:
		switch r := right.(type) {
		case map[string]interface{}:
			return mergeObjects(l, r)
		}
	case []interface{}:
		switch r := right.(type) {
		case []interface{}:
			length := len(l)
			if len(r) > length {
				length = len(r)
			}
			arr := make([]interface{}, length)
			for i := 0; i < length; i++ {
				if i < len(l) && i < len(r) {
					arr[i] = mergeDocuments(l[i], r[i])
				} else if i < len(l) {
					arr[i] = l[i]
				} else if i < len(r) {
					arr[i] = r[i]
				} else {
					arr[i] = nil
				}
			}
			return arr
		}
	}

	return left
}

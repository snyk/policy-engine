package rego

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"

	"github.com/open-policy-agent/opa/ast"
)

type Consumer interface {
	Module(path string, bytes []byte) error
	DataDocument(path string, bytes []byte) error
}

// An implementation that stores parsed modules and documents in-memory.
// It reads JSON and YAML files in addition to Rego files.
type BaseConsumer struct {
	Modules   map[string]*ast.Module
	Documents map[string]interface{}
}

func NewBaseConsumer() *BaseConsumer {
	return &BaseConsumer{
		Modules:   map[string]*ast.Module{},
		Documents: map[string]interface{}{},
	}
}

func (c *BaseConsumer) Module(path string, bytes []byte) error {
	if module, err := ast.ParseModule(path, string(bytes)); err == nil {
		c.Modules[path] = module
		return nil
	} else {
		return err
	}
}

func (c *BaseConsumer) DataDocument(path string, bytes []byte) error {
	switch filepath.Ext(path) {
	case ".json":
		document := map[string]interface{}{}
		if err := json.Unmarshal(bytes, &document); err != nil {
			return err
		}

		prefix := dataDocumentPrefix(path)
		for i := len(prefix) - 1; i >= 0; i-- {
			document = map[string]interface{}{
				prefix[i]: document,
			}
		}
		c.Documents = mergeObjects(c.Documents, document)
		return nil
	case ".yaml":
		return fmt.Errorf("%s: TODO: implement yaml", path)
	default:
		return fmt.Errorf("%s: unknown extension for DataDocument", path)
	}
}

// Returns a prefix to nest the document under based on the filename.  This
// matches the OPA behaviour.
//
//     rules/snyk_001/metadata.json
//
// Results in
//
//     ["rules", "snyk_001"]
func dataDocumentPrefix(path string) []string {
	prefix := []string{}
	for _, part := range regexp.MustCompile(`[/\\]+`).Split(filepath.Dir(path), -1) {
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

package data

import (
	"path/filepath"
	"strings"
)

// Returns a prefix to nest the document under based on the filename.  This
// matches the OPA behaviour.
//
//     metadata/rules/snyk_001/metadata.json
//
// Results in
//
//     ["rules", "snyk_001"]
func dataDocumentPrefix(basePath string, path string) []string {
	if basePath == path {
		return nil
	}

	rel, err := filepath.Rel(basePath, path)
	if err != nil {
		return nil
	}

	prefix := []string{}
	for _, part := range strings.Split(filepath.ToSlash(filepath.Dir(rel)), "/") {
		if part != "" {
			prefix = append(prefix, part)
		}
	}
	return prefix
}

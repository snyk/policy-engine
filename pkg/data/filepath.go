// Copyright 2022 Snyk Ltd
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
		if part != "" && part != "." {
			prefix = append(prefix, part)
		}
	}
	return prefix
}

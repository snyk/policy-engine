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

package legacyiac

import (
	"sort"
	"strings"

	"github.com/snyk/policy-engine/pkg/models"
)

type K8sInput struct {
	resourceNamespace string
	resourceType      string
	resourceId        string
	document          map[string]interface{}
}

func NewK8sInputs(state *models.State) []Input {
	inputs := []Input{}

	// Need to be deterministic for tests.
	resourceTypes := []string{}
	for resourceType := range state.Resources {
		resourceTypes = append(resourceTypes, resourceType)
	}
	sort.Strings(resourceTypes)

	for _, resourceType := range resourceTypes {
		resources := state.Resources[resourceType]

		// Need to be deterministic for tests.
		resourceKeys := []string{}
		for key := range resources {
			resourceKeys = append(resourceKeys, key)
		}
		sort.Strings(resourceKeys)

		for _, k := range resourceKeys {
			r := resources[k]
			input := K8sInput{
				resourceNamespace: r.Namespace,
				resourceType:      r.ResourceType,
				resourceId:        r.Id,
				document:          r.Attributes,
			}
			inputs = append(inputs, &input)
		}

	}

	return inputs
}

func (k *K8sInput) Raw() interface{} {
	return k.document
}

func (k *K8sInput) ParseMsg(msg string) ParsedMsg {
	path := parsePath(msg)

	// Some paths may start with "kind.", remove that part.
	if len(path) > 0 {
		if resourceType, ok := path[0].(string); ok &&
			strings.ToLower(resourceType) == strings.ToLower(k.resourceType) {
			path = path[1:]
		}
	}

	rewritePath(path, k.document)
	return ParsedMsg{
		ResourceID:        k.resourceId,
		ResourceType:      k.resourceType,
		ResourceNamespace: k.resourceNamespace,
		Path:              path,
	}
}

func rewritePath(path []interface{}, document interface{}) {
	cursor := document
	for pathIdx := range path {
		switch parent := cursor.(type) {
		case map[string]interface{}:
			switch k := path[pathIdx].(type) {
			case string:
				if child, ok := parent[k]; ok {
					cursor = child
					continue
				}
			}
		case []interface{}:
			switch i := path[pathIdx].(type) {
			case int:
				if i >= 0 && i < len(parent) {
					cursor = parent[i]
					continue
				}
			case string:
				for actual, elem := range parent {
					if obj, ok := elem.(map[string]interface{}); ok {
						if name, ok := obj["name"]; ok {
							if namestr := name.(string); ok && namestr == i {
								path[pathIdx] = actual
								cursor = elem
								continue
							}
						}
					}
				}
			}
		}

		// Stop on type mismatches and non-nested types.
		return
	}
}

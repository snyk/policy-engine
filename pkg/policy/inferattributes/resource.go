// Copyright 2022-2023 Snyk Ltd
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

package inferattributes

import (
	"os"

	"github.com/open-policy-agent/opa/ast"

	"github.com/snyk/policy-engine/pkg/models"
)

// DecorateResource is a helper that sets up DecorateTerm in a way that we
// will be able to tell which resource the values belonged to.
func DecorateResource(resource models.ResourceState, term *ast.Term) {
	prefix := []interface{}{
		resource.Namespace,
		resource.ResourceType,
		resource.Id,
	}

	DecorateTerm(prefix, term)
}

// byResource extracts the accessed attributes from the underlying pathset.
//
// It groups the resources per resource key (namespace, resource type, id).
func (tracer *Tracer) byResource() map[[3]string][][]interface{} {
	resources := map[[3]string][][]interface{}{}

	// Do not include paths starting with these fields.
	mask1 := map[string]struct{}{
		"id":         {},
		"_id":        {},
		"_meta":      {},
		"_namespace": {},
		"_type":      {},
	}

	for _, inputPath := range tracer.pathSet.List() {
		if len(inputPath) >= 3 {
			if resourceNamespace, ok := inputPath[0].(string); ok {
				if resourceType, ok := inputPath[1].(string); ok {
					if resourceId, ok := inputPath[2].(string); ok {
						key := [3]string{resourceNamespace, resourceType, resourceId}
						if _, ok := resources[key]; !ok {
							resources[key] = [][]interface{}{}
						}
						attribute := inputPath[3:]

						// Mask out certain attributes.
						if len(attribute) > 0 {
							if start, ok := attribute[0].(string); ok {
								if _, ok := mask1[start]; ok {
									continue
								}
							}
							resources[key] = append(resources[key], attribute)
						}
					}
				}
			}
		}
	}
	return resources
}

// InferAttributes decorates the given rule results with any attributes that
// have been accessed; using the resource identifiers to correlate them.
func (tracer *Tracer) InferAttributes(ruleResult []models.RuleResult) {
	resources := tracer.byResource()
	for _, rr := range ruleResult {
		for _, r := range rr.Resources {
			// FIXME: This is a bit of technical debt, but I think it is worth
			// leaving in for now as it allows developers to compare the
			// inferred attributes with the explicit ones without changing the
			// rego code.
			forceInferAttributes := os.Getenv("POLICY_ENGINE_FORCE_INFER_ATTRIBUTES") == "true"
			if len(r.Attributes) == 0 || forceInferAttributes {
				key := [3]string{
					r.Namespace,
					r.Type,
					r.Id,
				}
				if paths, ok := resources[key]; ok {
					r.Attributes = make([]models.RuleResultResourceAttribute, len(paths))
					for i := range paths {
						r.Attributes[i] = models.RuleResultResourceAttribute{
							Path: paths[i],
						}
					}
				}
			}
		}
	}
}

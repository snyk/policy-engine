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

package inferattributes

import (
	"github.com/open-policy-agent/opa/ast"

	"github.com/snyk/policy-engine/pkg/models"
)

func DecorateResource(resource models.ResourceState, value ast.Value) {
	prefix := []interface{}{
		resource.Namespace,
		resource.ResourceType,
		resource.Id,
	}

	DecorateValue(prefix, value)
}

func (tracer *Tracer) flushByResource() map[[3]string][][]interface{} {
	byResource := map[[3]string][][]interface{}{}
	inputPaths := tracer.flush()
	for _, inputPath := range inputPaths {
		if len(inputPath) >= 3 {
			if resourceNamespace, ok := inputPath[0].(string); ok {
				if resourceType, ok := inputPath[1].(string); ok {
					if resourceId, ok := inputPath[2].(string); ok {
						key := [3]string{resourceNamespace, resourceType, resourceId}
						if _, ok := byResource[key]; !ok {
							byResource[key] = [][]interface{}{}
						}
						byResource[key] = append(byResource[key], inputPath[3:])
					}
				}
			}
		}
	}
	return byResource
}

func (tracer *Tracer) InferAttributes(ruleResult []models.RuleResult) {
	// Fill in paths inferred using the tracer.
	byResource := tracer.flushByResource()
	for _, rr := range ruleResult {
		for _, r := range rr.Resources {
			if len(r.Attributes) == 0 {
				key := [3]string{
					r.Namespace,
					r.Type,
					r.Id,
				}
				if paths, ok := byResource[key]; ok {
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

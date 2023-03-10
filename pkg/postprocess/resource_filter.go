// © 2022-2023 Snyk Limited All rights reserved.
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

package postprocess

import (
	"github.com/snyk/policy-engine/pkg/models"
	"github.com/snyk/policy-engine/pkg/policy"
)

// Retain only resources that satisfy a given predicate, and filter down results
// to only retain results that correspond to these resources.
func ResourceFilter(
	results *models.Results,
	predicate func(*models.ResourceState) bool,
) {
	for i := range results.Results {
		resourceFilterResult(&results.Results[i], predicate)
	}
}

func resourceFilterResult(
	result *models.Result,
	predicate func(*models.ResourceState) bool,
) {
	// Keys to retain
	keys := map[policy.ResourceKey]struct{}{}

	// Filter down result.Input.Resources.  Store retained resource keys.
	outResourcesByType := map[string]map[string]models.ResourceState{}
	for inResourceType, inResources := range result.Input.Resources {
		outResources := map[string]models.ResourceState{}
		for inResourceId, inResource := range inResources {
			if predicate(&inResource) {
				outResources[inResourceId] = inResource
				keys[policy.ResourceKey{
					Namespace: inResource.Namespace,
					Type:      inResource.ResourceType,
					ID:        inResource.Id,
				}] = struct{}{}
			}
		}
		if len(outResources) > 0 {
			outResourcesByType[inResourceType] = outResources
		}
	}
	result.Input.Resources = outResourcesByType

	// Filter down result.RuleResults[_].Results
	for i, ruleResults := range result.RuleResults {
		outResults := []models.RuleResult{}
		for _, inResult := range ruleResults.Results {
			relevant := false
			for rk := range ruleResultResourceKeys(inResult) {
				if _, ok := keys[rk]; ok {
					relevant = relevant || true
				}
			}
			if relevant {
				outResults = append(outResults, inResult)
			}
		}
		result.RuleResults[i].Results = outResults
	}
}

// Set of all resource keys a rule result relates to.
func ruleResultResourceKeys(result models.RuleResult) map[policy.ResourceKey]struct{} {
	keys := map[policy.ResourceKey]struct{}{}

	if result.ResourceId != "" {
		keys[policy.ResourceKey{
			Namespace: result.ResourceNamespace,
			Type:      result.ResourceType,
			ID:        result.ResourceId,
		}] = struct{}{}
	}

	for _, resource := range result.Resources {
		keys[policy.ResourceKey{
			Namespace: resource.Namespace,
			Type:      resource.Type,
			ID:        resource.Id,
		}] = struct{}{}
	}

	return keys
}

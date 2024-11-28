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

package policy

import (
	"sort"
	"strings"

	"github.com/snyk/policy-engine/pkg/interfacetricks"
	"github.com/snyk/policy-engine/pkg/models"
)

// Helper for constructing results.  Takes care of grouping resources by
// namespace and ID and then merging the different pieces of information we
// obtain.
type ruleResultBuilder struct {
	passed            bool
	ignored           bool
	isMissingResource bool
	messages          []string
	resourceId        string
	resourceNamespace string
	resourceType      string
	remediation       string
	severity          string
	context           map[string]interface{}
	resources         map[ResourceKey]*models.RuleResultResource
	graphs            [][]models.Edge
}

func newRuleResultBuilder() *ruleResultBuilder {
	return &ruleResultBuilder{
		resources: map[ResourceKey]*models.RuleResultResource{},
	}
}

func (builder *ruleResultBuilder) setMissingResourceType(resourceType string) *ruleResultBuilder {
	builder.resourceType = resourceType
	builder.isMissingResource = true
	return builder
}

func (builder *ruleResultBuilder) setPrimaryResource(key ResourceKey) *ruleResultBuilder {
	builder.addResource(key)
	builder.resourceId = key.ID
	builder.resourceNamespace = key.Namespace
	builder.resourceType = key.Type
	return builder
}

func (builder *ruleResultBuilder) addResource(key ResourceKey) *ruleResultBuilder {
	if _, ok := builder.resources[key]; ok {
		return builder
	} else {
		builder.resources[key] = &models.RuleResultResource{
			Id:        key.ID,
			Namespace: key.Namespace,
			Type:      key.Type,
		}
		return builder
	}
}

func (builder *ruleResultBuilder) addResourceAttribute(
	key ResourceKey,
	attribute []interface{},
) *ruleResultBuilder {
	builder.addResource(key)
	resource := builder.resources[key]

	// Check if this path is already present
	present := false
	for _, e := range resource.Attributes {
		if interfacetricks.Equal(e.Path, attribute) {
			present = true
		}
	}

	if present {
		return builder
	}

	resource.Attributes = append(
		resource.Attributes,
		models.RuleResultResourceAttribute{
			Path: attribute,
		},
	)
	return builder
}

func (builder *ruleResultBuilder) addGraph(edges []policyResultEdge) *ruleResultBuilder {
	if len(edges) < 1 {
		return builder
	}

	graph := make([]models.Edge, len(edges))
	for idx, edge := range edges {
		source := edge.Source
		target := edge.Target
		graph[idx] = models.Edge{
			Label: edge.Label,
			Source: &models.Node{
				Id:        source.ID,
				Type:      source.Type,
				Namespace: source.Namespace,
			},
			Target: &models.Node{
				Id:        target.ID,
				Type:      target.Type,
				Namespace: target.Namespace,
			},
		}
	}
	builder.graphs = append(builder.graphs, graph)

	return builder
}

func (builder *ruleResultBuilder) addContext(context map[string]interface{}) *ruleResultBuilder {
	if len(context) == 0 {
		return builder
	}
	if builder.context == nil {
		builder.context = map[string]interface{}{}
	}
	for k, v := range context {
		builder.context[k] = v
	}
	return builder
}

func (builder *ruleResultBuilder) toRuleResult() models.RuleResult {
	// Gather resources.
	resourceKeys := []ResourceKey{}
	for k := range builder.resources {
		resourceKeys = append(resourceKeys, k)
	}
	sort.Slice(resourceKeys, func(i, j int) bool {
		return resourceKeys[i].Less(resourceKeys[j])
	})
	resources := []*models.RuleResultResource{}
	for _, k := range resourceKeys {
		resources = append(resources, builder.resources[k])
	}

	// Gather unique, non-blank messages.
	var messages []string
	seenMessages := map[string]bool{}
	for _, m := range builder.messages {
		if m == "" {
			continue
		}
		if _, seen := seenMessages[m]; !seen {
			messages = append(messages, m)
			seenMessages[m] = true
		}
	}
	sort.Strings(messages)

	// Infer primary resource.
	resourceId := builder.resourceId
	resourceNamespace := builder.resourceNamespace
	resourceType := builder.resourceType
	// Infer the primary resource automatically is there is only one resource, but
	// skip this step for "missing resource"-type rules.
	if !builder.isMissingResource && len(resources) == 1 {
		resource := resources[0]
		resourceId = resource.Id
		resourceNamespace = resource.Namespace
		resourceType = resource.Type
	}

	return models.RuleResult{
		Passed:            builder.passed,
		Ignored:           builder.ignored,
		Message:           strings.Join(messages, "\n\n"),
		ResourceId:        resourceId,
		ResourceNamespace: resourceNamespace,
		ResourceType:      resourceType,
		Remediation:       builder.remediation,
		Severity:          builder.severity,
		Context:           builder.context,
		Resources:         resources,
		Graphs:            builder.graphs,
	}
}

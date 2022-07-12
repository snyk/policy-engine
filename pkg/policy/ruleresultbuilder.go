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
	messages          []string
	resourceId        string
	resourceNamespace string
	resourceType      string
	remediation       string
	severity          string
	context           map[string]interface{}
	resources         map[ResourceKey]*models.RuleResultResource
}

func newRuleResultBuilder() *ruleResultBuilder {
	return &ruleResultBuilder{
		resources: map[ResourceKey]*models.RuleResultResource{},
	}
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

func (builder *ruleResultBuilder) toRuleResult() models.RuleResult {
	// Gather resources.  TODO: sort?
	resources := []*models.RuleResultResource{}
	for _, resource := range builder.resources {
		resources = append(resources, resource)
	}

	// Gather messages.
	messages := make([]string, len(builder.messages))
	copy(messages, builder.messages)
	sort.Strings(messages)

	// Infer primary resource.
	resourceId := builder.resourceId
	resourceNamespace := builder.resourceNamespace
	resourceType := builder.resourceType
	if len(resources) == 1 {
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
	}
}

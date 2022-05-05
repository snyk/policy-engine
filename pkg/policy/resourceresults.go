package policy

import (
	"github.com/snyk/unified-policy-engine/pkg/interfacetricks"
	"github.com/snyk/unified-policy-engine/pkg/models"
)

// Helper for constructing results by resource.  Takes care of grouping
// resources by namespace and ID and then merging the different pieces of
// information we obtain.
type resourceResults struct {
	byKey map[ResourceKey]models.RuleResultResource
}

func newResourceResults() *resourceResults {
	return &resourceResults{
		byKey: map[ResourceKey]models.RuleResultResource{},
	}
}

func (results *resourceResults) addRuleResultResource(
	result models.RuleResultResource,
) *resourceResults {
	key := ResourceKey{
		Namespace: result.Namespace,
		Type:      result.Type,
		ID:        result.Id,
	}
	if existing, ok := results.byKey[key]; ok {
		for _, attr := range result.Attributes {
			// Check if this path is already present
			present := false
			for _, e := range existing.Attributes {
				if interfacetricks.Equal(e.Path, attr.Path) {
					present = true
				}
			}

			if !present {
				existing.Attributes = append(
					existing.Attributes,
					models.RuleResultResourceAttribute{
						Path: attr.Path,
					},
				)
			}
		}
	} else {
		results.byKey[key] = result
	}
	return results
}

func (results *resourceResults) resources() []models.RuleResultResource {
	resources := []models.RuleResultResource{}
	for _, resource := range results.byKey {
		resources = append(resources, resource)
	}
	return resources
}

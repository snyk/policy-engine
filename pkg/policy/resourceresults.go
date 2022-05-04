package policy

import (
	"github.com/snyk/unified-policy-engine/pkg/interfacetricks"
	"github.com/snyk/unified-policy-engine/pkg/models"
)

// Helper for constructing results by resource.  Takes care of grouping
// resources by namespace and ID and then merging the different pieces of
// information we obtain.
type resourceResults struct {
	byNamespaceTypeId map[[3]string]models.RuleResultResource
}

func newResourceResults() *resourceResults {
	return &resourceResults{
		byNamespaceTypeId: map[[3]string]models.RuleResultResource{},
	}
}

func (results *resourceResults) addRuleResultResource(
	result models.RuleResultResource,
) *resourceResults {
	key := [3]string{result.Namespace, result.Type, result.Id}
	if existing, ok := results.byNamespaceTypeId[key]; ok {
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
		results.byNamespaceTypeId[key] = result
	}
	return results
}

func (results *resourceResults) resources() []models.RuleResultResource {
	resources := []models.RuleResultResource{}
	for _, resource := range results.byNamespaceTypeId {
		resources = append(resources, resource)
	}
	return resources
}

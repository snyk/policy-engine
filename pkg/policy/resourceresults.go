package policy

import (
	"github.com/snyk/unified-policy-engine/pkg/models"
)

// Helper for constructing results by resource.  Takes care of grouping
// resources by namespace and ID and then merging the different pieces of
// information we obtain.
type resourceResults struct {
	byNamespaceId map[[2]string]models.RuleResultResource
}

func newResourceResults() *resourceResults {
	return &resourceResults{
		byNamespaceId: map[[2]string]models.RuleResultResource{},
	}
}

func (results *resourceResults) addRuleResultResource(
	result models.RuleResultResource,
) *resourceResults {
	key := [2]string{result.Namespace, result.Id}
	if existing, ok := results.byNamespaceId[key]; ok {
		// TODO: Deduplicate using interfacetricks.Equal
		for _, attr := range result.Attributes {
			existing.Attributes = append(
				existing.Attributes,
				models.RuleResultResourceAttribute{
					Path: attr.Path,
				},
			)
		}
	} else {
		results.byNamespaceId[key] = result
	}
	return results
}

func (results *resourceResults) resources() []models.RuleResultResource {
	resources := []models.RuleResultResource{}
	for _, resource := range results.byNamespaceId {
		resources = append(resources, resource)
	}
	return resources
}

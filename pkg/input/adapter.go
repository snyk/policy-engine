package input

import "github.com/snyk/policy-engine/pkg/models"

func groupResourcesByType(
	resources []models.ResourceState,
) map[string]map[string]models.ResourceState {
	byType := map[string]map[string]models.ResourceState{}
	for _, resource := range resources {
		if _, ok := byType[resource.ResourceType]; !ok {
			byType[resource.ResourceType] = map[string]models.ResourceState{}
		}
		byType[resource.ResourceType][resource.Id] = resource
	}
	return byType
}

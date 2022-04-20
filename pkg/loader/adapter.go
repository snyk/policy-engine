package loader

import "github.com/snyk/unified-policy-engine/pkg/models"

func toState(
	inputType string,
	filepath string,
	resourceAttributes map[string]interface{},
) models.State {
	state := models.State{
		InputType:           inputType,
		EnvironmentProvider: "iac",
		Meta: map[string]interface{}{
			"filepath": filepath,
		},
		Resources: map[string]map[string]models.ResourceState{},
	}
	for resourceId, a := range resourceAttributes {
		attrs, ok := a.(map[string]interface{})
		if !ok {
			continue
		}
		rt, ok := attrs["_type"]
		if !ok {
			continue
		}
		resourceType, ok := rt.(string)
		if !ok {
			continue
		}
		resources, ok := state.Resources[resourceType]
		if !ok {
			resources = map[string]models.ResourceState{}
			state.Resources[resourceType] = resources
		}
		resources[resourceId] = models.ResourceState{
			Id:           resourceId,
			Attributes:   attrs,
			Namespace:    filepath,
			ResourceType: resourceType,
		}
	}
	return state
}

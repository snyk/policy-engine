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
		Resources: map[string]models.ResourceState{},
	}
	for resourceId, a := range resourceAttributes {
		attrs, ok := a.(map[string]interface{})
		if !ok {
			continue
		}
		resource := models.ResourceState{
			Id:         resourceId,
			Attributes: attrs,
			Namespace:  filepath,
		}
		if rt, ok := attrs["_type"]; ok {
			if resourceType, ok := rt.(string); ok {
				resource.ResourceType = resourceType
			}
		}
		state.Resources[resourceId] = resource
	}
	return state
}

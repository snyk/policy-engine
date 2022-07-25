package legacyiac

import (
	"github.com/snyk/policy-engine/pkg/models"
)

type CfnInput struct {
	resources map[string]map[string]interface{}
}

func NewCfnInput(state *models.State) *CfnInput {
	inputResources := map[string]map[string]interface{}{}
	for rt, resources := range state.Resources {
		for name, r := range resources {
			inputResources[name] = map[string]interface{}{
				"Type":       rt,
				"Properties": r.Attributes,
			}
		}
	}
	return &CfnInput{
		resources: inputResources,
	}
}

func (i *CfnInput) Raw() interface{} {
	return map[string]map[string]map[string]interface{}{
		"Resources": i.resources,
	}
}

func (i *CfnInput) ParseMsg(msg string) ParsedMsg {
	// Valid CFN messages look like:
	// 		Resources.SomeID
	// 		Resources.SomeID.Properties.SomeProperty
	// 		Resources[SomeID]Properties.SomeProperty.SomeSubProperty[0]
	path := parsePath(msg)
	pathLen := len(path)
	var resourceID string
	var resourceType string
	var attributePath []interface{}
	if pathLen >= 2 {
		// zero values are fine here
		resourceID = path[1].(string)
		if resource, ok := i.resources[resourceID]; ok {
			if t, ok := resource["Type"]; ok {
				resourceType = t.(string)
			}
		}
	}
	if pathLen >= 4 {
		attributePath = path[3:]
	}
	return ParsedMsg{
		ResourceID:   resourceID,
		ResourceType: resourceType,
		Path:         attributePath,
	}
}

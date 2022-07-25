package legacyiac

import (
	"github.com/snyk/policy-engine/pkg/models"
)

type ArmInput struct {
	resources []map[string]interface{}
}

func NewArmInput(state *models.State) *ArmInput {
	inputResources := []map[string]interface{}{}
	for rt, resources := range state.Resources {
		for name, r := range resources {
			inputResource := map[string]interface{}{}
			for k, v := range r.Attributes {
				inputResource[k] = v
			}
			inputResource["type"] = rt
			inputResource["name"] = name
			inputResources = append(inputResources, inputResource)
		}
	}
	return &ArmInput{
		resources: inputResources,
	}
}

func (i *ArmInput) Raw() interface{} {
	return map[string][]map[string]interface{}{
		"resources": i.resources,
	}
}

func (i *ArmInput) ParseMsg(msg string) ParsedMsg {
	// Valid tf messages look like:
	//		resources[0]
	//		resources[0].properties.some_property
	//		resources[0].properties.some_property.some_sub_property[0]
	//		resources[0].sku.name
	path := parsePath(msg)
	pathLen := len(path)
	var resourceID string
	var resourceType string
	var attributePath []interface{}
	if pathLen >= 2 {
		resourceIdx, ok := path[1].(int)
		if !ok {
			return ParsedMsg{}
		}
		if len(i.resources) <= resourceIdx {
			return ParsedMsg{}
		}
		resource := i.resources[resourceIdx]
		n, ok := resource["name"]
		if !ok {
			return ParsedMsg{}
		}
		resourceID, ok = n.(string)
		if !ok {
			return ParsedMsg{}
		}
		t, ok := resource["type"]
		if !ok {
			return ParsedMsg{}
		}
		resourceType, ok = t.(string)
		if !ok {
			return ParsedMsg{}
		}
	}
	if pathLen >= 3 {
		attributePath = path[2:]
	}
	return ParsedMsg{
		ResourceID:   resourceID,
		ResourceType: resourceType,
		Path:         attributePath,
	}
}

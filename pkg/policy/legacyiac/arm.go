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

type armInputState int

const (
	armInitial armInputState = iota
	armAfterResources
	armAfterResourceIdx
)

func (i *ArmInput) ParseMsg(msg string) ParsedMsg {
	// Valid tf messages look like:
	//		resources[0]
	//		resources[0].properties.some_property
	//		resources[0].properties.some_property.some_sub_property[0]
	//		resources[0].sku.name
	// var resourceID string
	// var resourceType string
	var resourceIdx int
	var resourceIdxParsed bool
	var attributePath []interface{}
	var state armInputState

	path := parsePath(msg)

	for _, ele := range path {
		switch state {
		case armInitial:
			switch v := ele.(type) {
			case string:
				if v == "resources" {
					state = armAfterResources
				}
			case int:
				resourceIdx = v
				resourceIdxParsed = true
				state = armAfterResourceIdx
			}
		case armAfterResources:
			if i, ok := ele.(int); ok {
				resourceIdx = i
				resourceIdxParsed = true
				state = armAfterResourceIdx
			}
		case armAfterResourceIdx:
			attributePath = append(attributePath, ele)
		}
	}

	var resourceID string
	var resourceType string

	if resourceIdxParsed && len(i.resources) > resourceIdx {
		resource := i.resources[resourceIdx]
		if n, ok := resource["name"]; ok {
			if n, ok := n.(string); ok {
				resourceID = n
			}
		}
		if t, ok := resource["type"]; ok {
			if t, ok := t.(string); ok {
				resourceType = t
			}
		}
	}

	return ParsedMsg{
		ResourceID:   resourceID,
		ResourceType: resourceType,
		Path:         attributePath,
	}
}

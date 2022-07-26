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

type cfnInputState int

const (
	cfnInitial cfnInputState = iota
	cfnAfterResources
	cfnAfterResourceID
	cfnAfterProperties
)

func (i *CfnInput) ParseMsg(msg string) ParsedMsg {
	// Valid CFN messages look like:
	// 		Resources.SomeID
	// 		Resources.SomeID.Properties.SomeProperty
	// 		Resources[SomeID]Properties.SomeProperty.SomeSubProperty[0]
	var resourceID string
	var resourceType string
	var attributePath []interface{}
	var state cfnInputState

	path := parsePath(msg)

	for _, ele := range path {
		switch state {
		case cfnInitial:
			if s, ok := ele.(string); ok {
				if s == "Resources" {
					state = cfnAfterResources
				} else {
					resourceID = s
					state = cfnAfterResourceID
				}
			}
		case cfnAfterResources:
			if s, ok := ele.(string); ok {
				resourceID = s
				state = cfnAfterResourceID
			}
		case cfnAfterResourceID:
			if s, ok := ele.(string); ok && s == "Properties" {
				state = cfnAfterProperties
			}
		case cfnAfterProperties:
			attributePath = append(attributePath, ele)
		}
	}

	if resourceID != "" {
		if resource, ok := i.resources[resourceID]; ok {
			if t, ok := resource["Type"]; ok {
				resourceType = t.(string)
			}
		}
	}

	return ParsedMsg{
		ResourceID:   resourceID,
		ResourceType: resourceType,
		Path:         attributePath,
	}
}

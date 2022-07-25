package legacyiac

import (
	"fmt"
	"strings"

	"github.com/snyk/policy-engine/pkg/models"
)

type TfInput struct {
	resources map[string]map[string]interface{}
	data      map[string]map[string]interface{}
}

func NewTfInput(state *models.State) *TfInput {
	inputResources := map[string]map[string]interface{}{}
	inputData := map[string]map[string]interface{}{}
	for rt, resources := range state.Resources {
		var coll map[string]map[string]interface{}
		// Have to assign this before modifying rt
		rtPrefix := rt + "."
		if strings.HasPrefix(rt, "data.") {
			coll = inputData

			rt = strings.TrimPrefix(rt, "data.")
		} else {
			coll = inputResources
		}
		inputResourceType := map[string]interface{}{}
		for id, r := range resources {
			name := strings.TrimPrefix(id, rtPrefix)
			inputResourceType[name] = r.Attributes
		}
		coll[rt] = inputResourceType
	}
	return &TfInput{
		resources: inputResources,
		data:      inputData,
	}
}

func (i *TfInput) Raw() interface{} {
	return map[string]map[string]map[string]interface{}{
		"resource": i.resources,
		"data":     i.data,
	}
}

func (i *TfInput) parseDataPath(path []interface{}) ParsedMsg {
	if len(path) < 3 {
		return ParsedMsg{}
	}
	resourceType, ok := path[1].(string)
	if !ok {
		return ParsedMsg{}
	}
	resourceType = fmt.Sprintf("data.%s", resourceType)
	resourceID, ok := path[2].(string)
	if !ok {
		return ParsedMsg{}
	}
	resourceID = fmt.Sprintf("%s.%s", resourceType, resourceID)
	var attributePath []interface{}
	if len(path) > 3 {
		attributePath = path[3:]
	}
	return ParsedMsg{
		ResourceID:   resourceID,
		ResourceType: resourceType,
		Path:         attributePath,
	}
}

func (i *TfInput) parseResourcePath(path []interface{}) ParsedMsg {
	if len(path) < 3 {
		return ParsedMsg{}
	}
	resourceType, ok := path[1].(string)
	if !ok {
		return ParsedMsg{}
	}
	resourceID, ok := path[2].(string)
	if !ok {
		return ParsedMsg{}
	}
	resourceID = fmt.Sprintf("%s.%s", resourceType, resourceID)
	var attributePath []interface{}
	if len(path) > 3 {
		attributePath = path[3:]
	}
	return ParsedMsg{
		ResourceID:   resourceID,
		ResourceType: resourceType,
		Path:         attributePath,
	}
}

func (i *TfInput) parseUnknownPath(path []interface{}) ParsedMsg {
	if len(path) < 2 {
		return ParsedMsg{}
	}
	resourceType, ok := path[0].(string)
	if !ok {
		return ParsedMsg{}
	}
	resourceID, ok := path[1].(string)
	if !ok {
		return ParsedMsg{}
	}
	// It's possible for names / types to be duplicated between data and managed
	// resources, like resource `"aws_s3_bucket" "foo"` and `data "aws_s3_bucket" "foo"`
	// So this isn't definitive, but it should hopefully be fine in most cases.
	if dataResources, ok := i.data[resourceType]; ok {
		if _, ok := dataResources[resourceID]; ok {
			resourceType = fmt.Sprintf("data.%s", resourceType)
		}
	}
	resourceID = fmt.Sprintf("%s.%s", resourceType, resourceID)
	var attributePath []interface{}
	if len(path) > 2 {
		attributePath = path[2:]
	}
	return ParsedMsg{
		ResourceID:   resourceID,
		ResourceType: resourceType,
		Path:         attributePath,
	}
}

func (i *TfInput) ParseMsg(msg string) ParsedMsg {
	// Valid tf messages look like:
	// 		resource.some_type.some_id
	// 		resource.some_type.some_id.some_property
	// 		resource.some_type[some_id].some_property.some_sub_property[0]
	// 		data.some_type[some_id].some_property.some_sub_property[0]
	// 		some_type[some_id].some_property.some_sub_property[0]
	path := parsePath(msg)
	if len(path) < 1 {
		return ParsedMsg{}
	}
	head, ok := path[0].(string)
	if !ok {
		return ParsedMsg{}
	}
	switch head {
	case "resource":
		return i.parseResourcePath(path)
	case "data":
		return i.parseDataPath(path)
	default:
		return i.parseUnknownPath(path)
	}
}

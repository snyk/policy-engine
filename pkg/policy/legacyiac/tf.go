// Copyright 2022-2023 Snyk Ltd
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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

type tfInputState int

const (
	tfInitial tfInputState = iota
	tfAfterSection
	tfAfterResourceType
	tfAfterResourceID
)

func (i *TfInput) ParseMsg(msg string) ParsedMsg {
	// Valid tf messages look like:
	// 		resource.some_type.some_id
	// 		resource.some_type.some_id.some_property
	// 		resource.some_type[some_id].some_property.some_sub_property[0]
	// 		data.some_type[some_id].some_property.some_sub_property[0]
	// 		some_type[some_id].some_property.some_sub_property[0]
	var section string
	var resourceID string
	var resourceType string
	var attributePath []interface{}
	var state tfInputState

	path := parsePath(msg)

	for _, ele := range path {
		switch state {
		case tfInitial:
			if s, ok := ele.(string); ok {
				switch s {
				case "resource":
					section = s
					state = tfAfterSection
				case "data":
					section = s
					state = tfAfterSection
				default:
					resourceType = s
					state = tfAfterResourceType
				}
			}
		case tfAfterSection:
			if s, ok := ele.(string); ok {
				resourceType = s
				state = tfAfterResourceType
			}
		case tfAfterResourceType:
			if s, ok := ele.(string); ok {
				resourceID = s
				state = tfAfterResourceID
			}
		case tfAfterResourceID:
			attributePath = append(attributePath, ele)
		}
	}

	if resourceID != "" && resourceType != "" {
		if section == "" {
			// Have to look back in the input to figure out if it's a data resource. If
			// we don't find the resource in data, we'll just treat it like a managed
			// resource.
			if t, ok := i.data[resourceType]; ok {
				if _, ok := t[resourceID]; ok {
					section = "data"
				}
			}
		}

		if section == "data" {
			resourceType = fmt.Sprintf("data.%s", resourceType)
			resourceID = fmt.Sprintf("%s.%s", resourceType, resourceID)
		} else {
			resourceID = fmt.Sprintf("%s.%s", resourceType, resourceID)
		}
	}

	return ParsedMsg{
		ResourceID:   resourceID,
		ResourceType: resourceType,
		Path:         attributePath,
	}
}

// © 2022-2023 Snyk Limited All rights reserved.
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

package legacyiac_test

import (
	"testing"

	"github.com/snyk/policy-engine/pkg/models"
	"github.com/snyk/policy-engine/pkg/policy/legacyiac"
	"github.com/stretchr/testify/assert"
)

func TestRawArmInput(t *testing.T) {
	for _, tc := range []struct {
		name     string
		state    *models.State
		expected map[string][]map[string]interface{}
	}{
		{
			name: "resources",
			state: &models.State{
				Resources: map[string]map[string]models.ResourceState{
					"Microsoft.Web/sites": {
						"allowed": {
							Attributes: map[string]interface{}{
								"apiVersion": "2018-02-01",
								"location":   "West Europe",
								"properties": map[string]interface{}{
									"httpsOnly": "true",
									"property": map[string]interface{}{
										"subProperty": []string{"foo"},
									},
								},
							},
						},
					},
				},
			},
			expected: map[string][]map[string]interface{}{
				"resources": {
					{
						"name":       "allowed",
						"type":       "Microsoft.Web/sites",
						"apiVersion": "2018-02-01",
						"location":   "West Europe",
						"properties": map[string]interface{}{
							"httpsOnly": "true",
							"property": map[string]interface{}{
								"subProperty": []string{"foo"},
							},
						},
					},
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output := legacyiac.NewArmInput(tc.state).Raw()
			assert.Equal(t, tc.expected, output)
		})
	}
}

func TestArmParseMsg(t *testing.T) {
	armInput := legacyiac.NewArmInput(&models.State{
		Resources: map[string]map[string]models.ResourceState{
			"Microsoft.Web/sites": {
				"allowed": {
					Attributes: map[string]interface{}{
						"apiVersion": "2018-02-01",
						"location":   "West Europe",
						"properties": map[string]interface{}{
							"httpsOnly": "true",
							"property": map[string]interface{}{
								"subProperty": []string{"foo"},
							},
						},
					},
				},
			},
		},
	})
	for _, tc := range []struct {
		msg      string
		expected legacyiac.ParsedMsg
	}{
		{
			msg: "input.resources[0].properties.property.subProperty[0]",
			expected: legacyiac.ParsedMsg{
				ResourceID:   "allowed",
				ResourceType: "Microsoft.Web/sites",
				Path:         []interface{}{"properties", "property", "subProperty", 0},
			},
		},
		{
			msg: "resources[0].properties.property.subProperty[0]",
			expected: legacyiac.ParsedMsg{
				ResourceID:   "allowed",
				ResourceType: "Microsoft.Web/sites",
				Path:         []interface{}{"properties", "property", "subProperty", 0},
			},
		},
		{
			msg: "resources.0.properties.property.subProperty[0]",
			expected: legacyiac.ParsedMsg{
				ResourceID:   "allowed",
				ResourceType: "Microsoft.Web/sites",
				Path:         []interface{}{"properties", "property", "subProperty", 0},
			},
		},
		{
			msg: "input.resources[0]",
			expected: legacyiac.ParsedMsg{
				ResourceID:   "allowed",
				ResourceType: "Microsoft.Web/sites",
				Path:         nil,
			},
		},
		{
			msg: "resources[0].location",
			expected: legacyiac.ParsedMsg{
				ResourceID:   "allowed",
				ResourceType: "Microsoft.Web/sites",
				Path:         []interface{}{"location"},
			},
		},
	} {
		t.Run(tc.msg, func(t *testing.T) {
			output := armInput.ParseMsg(tc.msg)
			assert.Equal(t, tc.expected, output)
		})
	}
}

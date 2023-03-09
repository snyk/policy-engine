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

func TestRawCfnInput(t *testing.T) {
	for _, tc := range []struct {
		name     string
		state    *models.State
		expected map[string]map[string]map[string]interface{}
	}{
		{
			name: "Resources",
			state: &models.State{
				Resources: map[string]map[string]models.ResourceState{
					"AWS::S3::Bucket": {
						"Bucket1": {
							Attributes: map[string]interface{}{
								"Property": map[string]interface{}{
									"SubProperty": []string{"foo"},
								},
							},
						},
					},
					"AWS::CloudTrail::Trail": {
						"CloudTrailLogging": {
							Attributes: map[string]interface{}{
								"OtherProperty": map[string]interface{}{
									"OtherSubProperty": []string{"bar"},
								},
							},
						},
					},
				},
			},
			expected: map[string]map[string]map[string]interface{}{
				"Resources": {
					"Bucket1": {
						"Type": "AWS::S3::Bucket",
						"Properties": map[string]interface{}{
							"Property": map[string]interface{}{
								"SubProperty": []string{"foo"},
							},
						},
					},
					"CloudTrailLogging": {
						"Type": "AWS::CloudTrail::Trail",
						"Properties": map[string]interface{}{
							"OtherProperty": map[string]interface{}{
								"OtherSubProperty": []string{"bar"},
							},
						},
					},
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output := legacyiac.NewCfnInput(tc.state).Raw()
			assert.Equal(t, tc.expected, output)
		})
	}
}

func TestCfnParseMsg(t *testing.T) {
	cfnInput := legacyiac.NewCfnInput(&models.State{
		Resources: map[string]map[string]models.ResourceState{
			"AWS::S3::Bucket": {
				"Bucket1": {
					Attributes: map[string]interface{}{
						"Property": map[string]interface{}{
							"SubProperty": []string{"foo"},
						},
					},
				},
			},
			"AWS::CloudTrail::Trail": {
				"CloudTrailLogging": {
					Attributes: map[string]interface{}{
						"OtherProperty": map[string]interface{}{
							"OtherSubProperty": []string{"bar"},
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
			msg: "input.Resources[Bucket1].Properties.Property.SubProperty[0]",
			expected: legacyiac.ParsedMsg{
				ResourceID:   "Bucket1",
				ResourceType: "AWS::S3::Bucket",
				Path:         []interface{}{"Property", "SubProperty", 0},
			},
		},
		{
			msg: "Resources[Bucket1].Properties.Property.SubProperty[0]",
			expected: legacyiac.ParsedMsg{
				ResourceID:   "Bucket1",
				ResourceType: "AWS::S3::Bucket",
				Path:         []interface{}{"Property", "SubProperty", 0},
			},
		},
		{
			msg: "Resources.Bucket1.Properties.Property.SubProperty[0]",
			expected: legacyiac.ParsedMsg{
				ResourceID:   "Bucket1",
				ResourceType: "AWS::S3::Bucket",
				Path:         []interface{}{"Property", "SubProperty", 0},
			},
		},
		{
			msg: "Resources[CloudTrailLogging].Properties.OtherProperty",
			expected: legacyiac.ParsedMsg{
				ResourceID:   "CloudTrailLogging",
				ResourceType: "AWS::CloudTrail::Trail",
				Path:         []interface{}{"OtherProperty"},
			},
		},
		{
			msg: "Resources[CloudTrailLogging]",
			expected: legacyiac.ParsedMsg{
				ResourceID:   "CloudTrailLogging",
				ResourceType: "AWS::CloudTrail::Trail",
				Path:         nil,
			},
		},
	} {
		t.Run(tc.msg, func(t *testing.T) {
			output := cfnInput.ParseMsg(tc.msg)
			assert.Equal(t, tc.expected, output)
		})
	}
}

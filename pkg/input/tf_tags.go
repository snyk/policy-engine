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

package input

import (
	"strings"

	"github.com/snyk/policy-engine/pkg/models"
)

// tfExtractTags attempts to extract the tags from a resource's attributes.
// This should work for all terraform-based providers.
func tfExtractTags(model models.ResourceState) map[string]string {
	found := map[string]interface{}{}
	if model.ResourceType == "aws_autoscaling_group" {
		if arr, ok := model.Attributes["tag"].([]interface{}); ok {
			for i := range arr {
				if obj, ok := arr[i].(map[string]interface{}); ok {
					if key, ok := obj["key"].(string); ok {
						if value, ok := obj["value"]; ok {
							found[key] = value
						}
					}
				}
			}
		}
	}

	if strings.HasPrefix(model.ResourceType, "google_") {
		if tags, ok := model.Attributes["labels"].(map[string]interface{}); ok {
			for k, v := range tags {
				found[k] = v
			}
		}
		if tags, ok := model.Attributes["tags"].([]interface{}); ok {
			for _, key := range tags {
				if str, ok := key.(string); ok {
					found[str] = nil
				}
			}
		}
	} else {
		if tags, ok := model.Attributes["tags"].(map[string]interface{}); ok {
			for k, v := range tags {
				found[k] = v
			}
		}
	}

	// Keep only string tags, convert nil to "".
	sanitized := map[string]string{}
	for k, v := range found {
		if str, ok := v.(string); ok {
			sanitized[k] = str
		} else if v == nil {
			sanitized[k] = ""
		}
	}

	return sanitized
}

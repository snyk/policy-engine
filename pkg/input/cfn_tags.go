// © 2023 Snyk Limited All rights reserved.
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
	"github.com/snyk/policy-engine/pkg/models"
)

func cfnExtractTags(model models.ResourceState) map[string]string {
	found := map[string]string{}

	// Parse {$K: $V} style tags
	if tags, ok := model.Attributes["Tags"].(map[string]interface{}); ok {
		for key, val := range tags {
			if val, ok := val.(string); ok {
				found[key] = val
			}
		}
	}

	// Parse [{"Key": $K, "Value": $V}] style tags
	if tags, ok := model.Attributes["Tags"].([]interface{}); ok {
		for _, tag := range tags {
			if tag, ok := tag.(map[string]interface{}); ok {
				if key := tag["Key"].(string); ok {
					if val := tag["Value"].(string); ok {
						found[key] = val
					}
				}
			}
		}
	}

	return found
}

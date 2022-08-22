// Copyright 2022 Snyk Ltd
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

import "github.com/snyk/policy-engine/pkg/models"

func groupResourcesByType(
	resources []models.ResourceState,
) map[string]map[string]models.ResourceState {
	byType := map[string]map[string]models.ResourceState{}
	for _, resource := range resources {
		if _, ok := byType[resource.ResourceType]; !ok {
			byType[resource.ResourceType] = map[string]models.ResourceState{}
		}
		byType[resource.ResourceType][resource.Id] = resource
	}
	return byType
}

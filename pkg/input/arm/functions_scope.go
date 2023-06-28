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

package arm

import "fmt"

// Return a stub
// https://learn.microsoft.com/en-us/azure/azure-resource-manager/templates/template-functions-scope#resourcegroup
func resourceGroupImpl(e *EvaluationContext, args ...interface{}) (interface{}, error) {
	if len(args) != 0 {
		return nil, fmt.Errorf("expected zero args to resourceGroup(), got %d", len(args))
	}

	return map[string]interface{}{
		"id":         "stub-id",
		"name":       "stub-name",
		"type":       "stub-type",
		"location":   "stub-location",
		"managedBy":  "stub-managed-by",
		"tags":       map[string]interface{}{},
		"properties": map[string]interface{}{},
	}, nil
}

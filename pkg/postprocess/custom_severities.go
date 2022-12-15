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

package postprocess

import (
	"strings"

	models "github.com/snyk/policy-engine/pkg/models/latest"
)

type CustomSeverities map[string]string

// Override severities in the results with custom severities passed in.
// Severities are stored by rule ID.
// Setting severity of a rule ID to "none" effectively removes that
// rule from the results.
func ApplyCustomSeverities(
	results *models.Results,
	customSeverities CustomSeverities,
) {
	for i := range results.Results {
		updatedRuleResults := []models.RuleResults{}
		for _, result := range results.Results[i].RuleResults {
			if customSeverity, ok := customSeverities[result.Id]; ok {
				if strings.ToLower(customSeverity) == "none" {
					continue
				}

				for j := range result.Results {
					result.Results[j].Severity = customSeverity
				}
			}

			updatedRuleResults = append(updatedRuleResults, result)
		}
		results.Results[i].RuleResults = updatedRuleResults
	}
}

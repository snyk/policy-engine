package models

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

type mockReport struct {
	RuleResults map[string]RuleResults `json:"rule_results"`
}

func TestUnmarshalRuleResults(t *testing.T) {
	tests := []struct {
		serialized string
		expected   mockReport
	}{
		{
			`{
                "rule_results": {
                    "foo": {
                        "controls": {
                            "CIS-AWS": {
                              "v1.3.0": [
                                "5.1",
                                "5.2"
                              ],
                              "v1.4.0": [
                                "6.7"
                              ]
                            }
                        }
                    }
                }
            }`,
			mockReport{
				RuleResults: map[string]RuleResults{
					"foo": {
						Controls: []string{
							"CIS-AWS_v1.3.0_5.1",
							"CIS-AWS_v1.3.0_5.2",
							"CIS-AWS_v1.4.0_6.7",
						},
					},
				},
			},
		},
		{
			`{
                "rule_results": {
                    "foo": {
                        "controls": [
							"CIS-AWS_v1.3.0_5.1",
							"CIS-AWS_v1.3.0_5.2",
							"CIS-AWS_v1.4.0_6.7"
                        ]
                    }
                }
            }`,
			mockReport{
				RuleResults: map[string]RuleResults{
					"foo": {
						Controls: []string{
							"CIS-AWS_v1.3.0_5.1",
							"CIS-AWS_v1.3.0_5.2",
							"CIS-AWS_v1.4.0_6.7",
						},
					},
				},
			},
		},
	}
	for i, test := range tests {
		t.Run(fmt.Sprintf("case %d", i), func(t *testing.T) {
			actual := mockReport{}
			assert.NoError(t, json.Unmarshal([]byte(test.serialized), &actual))
			assert.Equal(t, test.expected, actual)
		})
	}
}

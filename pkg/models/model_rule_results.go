/*
 * Unified Policy Engine I/O Formats
 *
 * Documentation for the input and output formats used in Unified Policy Engine
 *
 * API version: 1.0.0
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */
package models

// Container for all results associated with a single rule
type RuleResults struct {
	// The Rule ID, e.g. SNYK_00503 or 608f97c3-a11a-4154-a88e-a2fcd18c75b0
	Id string `json:"id,omitempty"`
	// The rule title
	Title string `json:"title,omitempty"`
	// The rule description
	Description string `json:"description,omitempty"`
	// A markdown formatted string containing useful links
	References string `json:"references,omitempty"`
	// A map of rule set ID to a list of control tags
	Controls map[string][]string `json:"controls,omitempty"`
	// A list of rule set IDs associated with this rule
	RuleSets []string `json:"rule_sets,omitempty"`
	// A list of resource types that the rule uses.
	ResourceTypes []string     `json:"resource_types,omitempty"`
	Results       []RuleResult `json:"results"`
}

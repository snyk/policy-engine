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
	// The platform describes the CSPs or other technology platform (e.g. Docker) that the rule checks for
	Platform []string `json:"platform,omitempty"`
	// The rule description
	Description string `json:"description,omitempty"`
	// A markdown formatted string containing useful links
	References string `json:"references,omitempty"`
	// The category of the policy
	Category string `json:"category,omitempty"`
	// An array of tag key-value pairs associated with this policy. Values may be `null` for key-only tags.
	Tags map[string]interface{} `json:"tags,omitempty"`
	// The service group of the primary resource associated with this policy (e.g. \"EBS\", \"EC2\")
	ServiceGroup string `json:"service_group,omitempty"`
	// A map of rule set ID to a map of versions to a list of control IDs
	Controls map[string]map[string][]string `json:"controls,omitempty"`
	// A list of resource types that the rule uses.
	ResourceTypes []string     `json:"resource_types,omitempty"`
	Results       []RuleResult `json:"results"`
	// Any errors that occurred while evaluating this rule.
	Errors []string `json:"errors,omitempty"`
	// The Rego package name that defines the rule, useful for debugging
	Package_ string `json:"package,omitempty"`
}

/*
 * Policy Engine I/O Formats
 *
 * Documentation for the input and output formats used in Policy Engine
 *
 * API version: 1.0.0
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */
package models

// Records an error that occurred while initializing a rule bundle
type RuleBundleErrors struct {
	RuleBundle *RuleBundleInfo `json:"rule_bundle,omitempty"`
	Errors     []string        `json:"errors,omitempty"`
}

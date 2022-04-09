package policy

import (
	"github.com/open-policy-agent/opa/rego"
	"github.com/snyk/unified-policy-engine/pkg/models"
)

// This file contains code for backwards compatibility with Fugue rules.

func processFugueAllowBoolean(
	resultSet rego.ResultSet,
	resource *models.ResourceState,
	metadata Metadata,
) ([]models.RuleResult, error) {
	var allow bool
	unmarshalResultSet(resultSet, &allow)
	// TODO: propagate remediation from metadata
	result := models.RuleResult{
		Passed:     allow,
		ResourceId: resource.Id,
		Severity:   metadata.Severity,
	}
	return []models.RuleResult{result}, nil
}

func processFugueDenyBoolean(
	resultSet rego.ResultSet,
	resource *models.ResourceState,
	metadata Metadata,
) ([]models.RuleResult, error) {
	var deny bool
	unmarshalResultSet(resultSet, &deny)
	result := models.RuleResult{
		Passed:     !deny,
		ResourceId: resource.Id,
		Severity:   metadata.Severity,
	}
	return []models.RuleResult{result}, nil
}

func processFuguePolicyResultSet(
	resultSet rego.ResultSet,
	metadata Metadata,
	_ map[string]map[string]models.RuleResultResource,
) ([]models.RuleResult, error) {
	policyResults := []policyResult{}
	if err := unmarshalResultSet(resultSet, &policyResults); err != nil {
		return nil, err
	}
	results := []models.RuleResult{}
	for _, p := range policyResults {
		result := models.RuleResult{
			Passed:       p.FugueValid,
			ResourceId:   p.FugueID,
			Message:      p.Message,
			Severity:     metadata.Severity,
			ResourceType: p.FugueResourceType,
		}
		results = append(results, result)
	}
	return results, nil
}

// This is a ProcessSingleResultSet func for the old allow[info] style rules
func processFugueAllowPolicyResult(
	resultSet rego.ResultSet,
	resource *models.ResourceState,
	metadata Metadata,
) ([]models.RuleResult, error) {
	policyResults := []policyResult{}
	if err := unmarshalResultSet(resultSet, &policyResults); err != nil {
		return nil, err
	}
	results := []models.RuleResult{}
	for _, r := range policyResults {
		result := models.RuleResult{
			Passed:     true,
			Message:    r.Message,
			ResourceId: resource.Id,
			Severity:   metadata.Severity,
		}
		results = append(results, result)
	}
	return results, nil
}

type metadocCustom struct {
	Severity  string              `json:"severity"`
	Controls  map[string][]string `json:"controls"`
	Families  []string            `json:"families"`
	Provider  string              `json:"provider"`
	Providers []string            `json:"providers"`
}

type metadoc struct {
	Id          string         `json:"id"`
	Title       string         `json:"title"`
	Description string         `json:"description"`
	Custom      *metadocCustom `json:"custom,omitempty"`
}

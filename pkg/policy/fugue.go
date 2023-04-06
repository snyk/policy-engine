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

package policy

import (
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"

	"github.com/snyk/policy-engine/pkg/models"
	"github.com/snyk/policy-engine/pkg/regobind"
)

// This file contains code for backwards compatibility with Fugue rules.

type fugueAllowBooleanResultBuilder struct {
	resource *models.ResourceState
	severity string
	allow    bool
}

func NewFugueAllowBooleanResultBuilder(
	resource *models.ResourceState,
	metadata *Metadata,
	defaultRemediation string,
) ResultBuilder {
	return &fugueAllowBooleanResultBuilder{
		resource: resource,
		severity: metadata.Severity,
	}
}

func (b *fugueAllowBooleanResultBuilder) Process(val ast.Value) error {
	return regobind.Bind(val, &b.allow)
}

func (b *fugueAllowBooleanResultBuilder) Results() []models.RuleResult {
	return []models.RuleResult{
		{
			Passed:            b.allow,
			ResourceId:        b.resource.Id,
			ResourceType:      b.resource.ResourceType,
			ResourceNamespace: b.resource.Namespace,
			Severity:          b.severity,
		},
	}
}

func processFugueDenyBoolean(
	resultSet rego.ResultSet,
	resource *models.ResourceState,
	metadata Metadata,
	_ string,
) ([]models.RuleResult, error) {
	var deny bool
	if err := unmarshalResultSet(resultSet, &deny); err != nil {
		return nil, err
	}
	result := models.RuleResult{
		Passed:            !deny,
		ResourceId:        resource.Id,
		ResourceType:      resource.ResourceType,
		ResourceNamespace: resource.Namespace,
		Severity:          metadata.Severity,
	}
	return []models.RuleResult{result}, nil
}

func processFugueAllowString(
	resultSet rego.ResultSet,
	resource *models.ResourceState,
	metadata Metadata,
	_ string,
) ([]models.RuleResult, error) {
	messages := []string{}
	if err := unmarshalResultSet(resultSet, &messages); err != nil {
		return nil, err
	}
	var allow bool
	var message string
	if len(messages) > 0 {
		allow = true
		message = messages[0]
	}
	result := models.RuleResult{
		Passed:            allow,
		ResourceId:        resource.Id,
		ResourceType:      resource.ResourceType,
		ResourceNamespace: resource.Namespace,
		Severity:          metadata.Severity,
		Message:           message,
	}
	return []models.RuleResult{result}, nil
}

func processFugueDenyString(
	resultSet rego.ResultSet,
	resource *models.ResourceState,
	metadata Metadata,
) ([]models.RuleResult, error) {
	messages := []string{}
	if err := unmarshalResultSet(resultSet, &messages); err != nil {
		return nil, err
	}
	var deny bool
	var message string
	if len(messages) > 0 {
		deny = true
		message = messages[0]
	}
	result := models.RuleResult{
		Passed:            !deny,
		ResourceId:        resource.Id,
		ResourceType:      resource.ResourceType,
		ResourceNamespace: resource.Namespace,
		Severity:          metadata.Severity,
		Message:           message,
	}
	return []models.RuleResult{result}, nil
}

func processFuguePolicyResultSet(
	resultSet rego.ResultSet,
	metadata Metadata,
	_ string,
	_ map[string]*ruleResultBuilder,
) ([]models.RuleResult, error) {
	policyResults := []policyResult{}
	if err := unmarshalResultSet(resultSet, &policyResults); err != nil {
		return nil, err
	}
	results := []models.RuleResult{}
	for _, p := range policyResults {
		result := models.RuleResult{
			Passed:            p.FugueValid,
			ResourceId:        p.FugueID,
			ResourceType:      p.FugueResourceType,
			ResourceNamespace: p.FugueResourceNamespace,
			Message:           p.Message,
			Severity:          metadata.Severity,
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
	_ string,
) ([]models.RuleResult, error) {
	policyResults := []policyResult{}
	if err := unmarshalResultSet(resultSet, &policyResults); err != nil {
		// It might be a fugue allow[msg] style rule in this case. Try that as a
		// fallback.
		return processFugueAllowString(resultSet, resource, metadata, "")
	}
	results := []models.RuleResult{}
	for _, r := range policyResults {
		result := models.RuleResult{
			Passed:            true,
			Message:           r.Message,
			ResourceId:        resource.Id,
			ResourceType:      resource.ResourceType,
			ResourceNamespace: resource.Namespace,
			Severity:          metadata.Severity,
		}
		results = append(results, result)
	}

	if len(results) == 0 {
		// No allows: generate a deny
		result := models.RuleResult{
			Passed:            false,
			ResourceId:        resource.Id,
			ResourceType:      resource.ResourceType,
			ResourceNamespace: resource.Namespace,
			Severity:          metadata.Severity,
		}
		results = append(results, result)
	}

	return results, nil
}

type metadocCustom struct {
	Severity  string              `json:"severity" rego:"severity"`
	Controls  map[string][]string `json:"controls" rego:"controls"`
	Families  []string            `json:"families" rego:"families"`
	Provider  string              `json:"provider" rego:"provider"`
	Providers []string            `json:"providers" rego:"providers"`
}

type metadoc struct {
	Id          string         `json:"id" rego:"id"`
	Title       string         `json:"title" rego:"title"`
	Description string         `json:"description" rego:"description"`
	Custom      *metadocCustom `json:"custom,omitempty" rego:"custom"`
}

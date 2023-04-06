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

type fugueDenyBooleanResultBuilder struct {
	resource *models.ResourceState
	severity string
	deny     bool
}

func NewFugueDenyBooleanResultBuilder(
	resource *models.ResourceState,
	metadata *Metadata,
	defaultRemediation string,
) ResultBuilder {
	return &fugueDenyBooleanResultBuilder{
		resource: resource,
		severity: metadata.Severity,
	}
}

func (b *fugueDenyBooleanResultBuilder) Process(val ast.Value) error {
	return regobind.Bind(val, &b.deny)
}

func (b *fugueDenyBooleanResultBuilder) Results() []models.RuleResult {
	return []models.RuleResult{
		{
			Passed:            !b.deny,
			ResourceId:        b.resource.Id,
			ResourceType:      b.resource.ResourceType,
			ResourceNamespace: b.resource.Namespace,
			Severity:          b.severity,
		},
	}
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

// This is a ProcessSingleResultSet func for the old allow[info] and
// allow[msg] style rules.
type fugueAllowInfoResultBuilder struct {
	resource *models.ResourceState
	severity string
	results  []models.RuleResult
}

func NewFugueAllowInfoResultBuilder(
	resource *models.ResourceState,
	metadata *Metadata,
	defaultRemediation string,
) ResultBuilder {
	return &fugueAllowInfoResultBuilder{
		resource: resource,
		severity: metadata.Severity,
	}
}

func (b *fugueAllowInfoResultBuilder) Process(val ast.Value) error {
	var r policyResult
	if err := regobind.Bind(val, &r); err != nil {
		// It might be a fugue allow[msg] style rule in this case. Try that as a
		// fallback.
		if strErr := regobind.Bind(val, &r.Message); strErr != nil {
			return err
		}
	}

	b.results = append(b.results, models.RuleResult{
		Passed:            true,
		Message:           r.Message,
		ResourceId:        b.resource.Id,
		ResourceType:      b.resource.ResourceType,
		ResourceNamespace: b.resource.Namespace,
		Severity:          b.severity,
	})
	return nil
}

func (b *fugueAllowInfoResultBuilder) Results() []models.RuleResult {
	if len(b.results) == 0 {
		// No allows: generate a deny
		return []models.RuleResult{
			{
				Passed:            false,
				ResourceId:        b.resource.Id,
				ResourceType:      b.resource.ResourceType,
				ResourceNamespace: b.resource.Namespace,
				Severity:          b.severity,
			},
		}
	} else {
		return b.results
	}
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

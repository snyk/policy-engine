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

	"github.com/snyk/policy-engine/pkg/models"
	"github.com/snyk/policy-engine/pkg/rego"
)

// This file contains code for backwards compatibility with Fugue rules.

type fugueAllowBooleanProcessor struct {
	resource *models.ResourceState
	severity string
	allow    bool
}

func NewFugueAllowBooleanProcessor(
	resource *models.ResourceState,
	metadata *Metadata,
	defaultRemediation string,
) SingleResourceProcessor {
	return &fugueAllowBooleanProcessor{
		resource: resource,
		severity: metadata.Severity,
	}
}

func (b *fugueAllowBooleanProcessor) Process(val ast.Value) error {
	return rego.Bind(val, &b.allow)
}

func (b *fugueAllowBooleanProcessor) Results() []models.RuleResult {
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

type fugueDenyBooleanProcessor struct {
	resource *models.ResourceState
	severity string
	deny     bool
}

func NewFugueDenyBooleanProcessor(
	resource *models.ResourceState,
	metadata *Metadata,
	defaultRemediation string,
) SingleResourceProcessor {
	return &fugueDenyBooleanProcessor{
		resource: resource,
		severity: metadata.Severity,
	}
}

func (b *fugueDenyBooleanProcessor) Process(val ast.Value) error {
	return rego.Bind(val, &b.deny)
}

func (b *fugueDenyBooleanProcessor) Results() []models.RuleResult {
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

type fuguePolicyProcessor struct {
	metadata Metadata
	results  []models.RuleResult
}

func NewFuguePolicyProcessor(metadata Metadata, defaultRemediation string) MultiResourceProcessor {
	return &fuguePolicyProcessor{
		metadata: metadata,
	}
}

func (p *fuguePolicyProcessor) ProcessValue(val ast.Value) error {
	var result policyResult
	if err := rego.Bind(val, &result); err != nil {
		return err
	}
	p.results = append(p.results, models.RuleResult{
		Passed:            result.FugueValid,
		ResourceId:        result.FugueID,
		ResourceType:      result.FugueResourceType,
		ResourceNamespace: result.FugueResourceNamespace,
		Message:           result.Message,
		Severity:          p.metadata.Severity,
	})
	return nil
}

func (p *fuguePolicyProcessor) ProcessResource(val ast.Value) error {
	return nil
}

func (p *fuguePolicyProcessor) Results() []models.RuleResult {
	return p.results
}

// This is a ProcessSingleResultSet func for the old allow[info] and
// allow[msg] style rules.
type fugueAllowInfoProcessor struct {
	resource *models.ResourceState
	severity string
	results  []models.RuleResult
}

func NewFugueAllowInfoProcessor(
	resource *models.ResourceState,
	metadata *Metadata,
	defaultRemediation string,
) SingleResourceProcessor {
	return &fugueAllowInfoProcessor{
		resource: resource,
		severity: metadata.Severity,
	}
}

func (b *fugueAllowInfoProcessor) Process(val ast.Value) error {
	var r policyResult
	if err := rego.Bind(val, &r); err != nil {
		// It might be a fugue allow[msg] style rule in this case. Try that as a
		// fallback.
		if strErr := rego.Bind(val, &r.Message); strErr != nil {
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

func (b *fugueAllowInfoProcessor) Results() []models.RuleResult {
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

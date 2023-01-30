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

package engine

import (
	"context"
	"sort"

	"github.com/open-policy-agent/opa/rego"
	"github.com/snyk/policy-engine/pkg/bundle"
	"github.com/snyk/policy-engine/pkg/data"
	"github.com/snyk/policy-engine/pkg/logging"
	"github.com/snyk/policy-engine/pkg/metrics"
	"github.com/snyk/policy-engine/pkg/models"
	"github.com/snyk/policy-engine/pkg/policy"
)

// Engine is responsible for evaluating some States with a given set of rules.
type Engine struct {
	instrumentation *engineInstrumentation
	policySets      []*policySet
	errors          []error
}

// EngineOptions contains options for initializing an Engine instance
type EngineOptions struct {
	// Providers contains functions that produce parsed OPA modules or data documents.
	Providers []data.Provider

	// Providers contains bundle.Reader objects that produce parsed bundles.
	BundleReaders []bundle.Reader

	// Logger is an optional instance of the logger.Logger interface
	Logger logging.Logger

	// Metrics is an optional instance of the metrics.Metrics interface
	Metrics metrics.Metrics
}

// NewEngine constructs a new Engine instance.
func NewEngine(ctx context.Context, options *EngineOptions) (*Engine, error) {
	logger := options.Logger
	if logger == nil {
		logger = logging.DefaultLogger
	}
	m := options.Metrics
	if m == nil {
		m = metrics.NewLocalMetrics(logger)
	}
	eng := &Engine{
		instrumentation: &engineInstrumentation{
			instrumentation: newInstrumentation(instrumentationOptions{
				component: "policy_engine",
				logger:    logger,
				metrics:   m,
			}),
		},
	}
	eng.instrumentation.startInitialization(ctx)
	if err := eng.initPolicySets(ctx, options.Providers, options.BundleReaders); err != nil {
		return nil, err
	}
	eng.instrumentation.finishInitialization(ctx)
	return eng, nil
}

func (e *Engine) initPolicySets(ctx context.Context, providers []data.Provider, readers []bundle.Reader) error {
	e.instrumentation.startInitializePolicySets(ctx)
	if len(providers) > 0 {
		policySet, err := newPolicySet(ctx, policySetOptions{
			providers: providers,
			source:    POLICY_SOURCE_DATA,
			instrumentation: e.instrumentation.child(
				metrics.Labels{
					"policy_set_source": string(POLICY_SOURCE_DATA),
				},
				info,
				withField("policy_set_source", string(POLICY_SOURCE_DATA)),
			),
		})
		if err != nil {
			return err
		}
		e.policySets = append(e.policySets, policySet)
	}

	for _, r := range readers {
		b, err := bundle.NewBundle(r)
		if err != nil {
			e.errors = append(e.errors, err)
			continue
		}
		sourceInfo := b.SourceInfo()
		var policySource PolicySource
		if sourceInfo.SourceType == bundle.ARCHIVE {
			policySource = POLICY_SOURCE_BUNDLE_ARCHIVE
		} else if sourceInfo.SourceType == bundle.DIRECTORY {
			policySource = POLICY_SOURCE_BUNDLE_DIRECTORY
		}
		labels := metrics.Labels{
			"policy_set_source": string(policySource),
			"policy_set_name":   sourceInfo.FileInfo.Path,
		}
		fields := []loggerOption{
			withField("policy_set_source", string(policySource)),
			withField("policy_set_name", sourceInfo.FileInfo.Path),
		}
		if sourceInfo.FileInfo.Checksum != "" {
			labels["policy_set_checksum"] = sourceInfo.FileInfo.Checksum
			fields = append(fields, withField("policy_set_checksum", sourceInfo.FileInfo.Checksum))
		}
		policySet, err := newPolicySet(ctx, policySetOptions{
			providers: []data.Provider{b.Provider()},
			source:    policySource,
			name:      sourceInfo.FileInfo.Path,
			checksum:  sourceInfo.FileInfo.Checksum,
			instrumentation: e.instrumentation.child(
				labels,
				info,
				fields...,
			),
		})
		if err != nil {
			return err
		}
		e.policySets = append(e.policySets, policySet)
	}
	e.instrumentation.finishInitializePolicySets(ctx)
	return nil
}

type policyResults struct {
	err         error
	ruleResults []models.RuleResults
}

// EvalOptions contains options for Engine.Eval
type EvalOptions struct {
	// Inputs are the State instances that the engine should evaluate.
	Inputs []models.State

	// Workers sets how many policies are to be evaluated concurrently. When
	// unset or set to a value less than 1, this defaults to the number of CPU
	// cores - 1.
	Workers int

	// ResourceResolver is a function that returns a resource state for the given
	// ResourceRequest.
	// Multiple ResourcesResolvers can be composed with And() and Or().
	ResourcesResolver policy.ResourcesResolver

	// RuleIDs determines which rules are executed. When this option is empty or
	// unspecified, all rules will be run.
	RuleIDs []string
}

// Eval evaluates the given states using the rules that the engine was initialized with.
func (e *Engine) Eval(ctx context.Context, options *EvalOptions) *models.Results {
	e.instrumentation.startEvaluate(ctx)
	results := []models.Result{}
	for _, input := range options.Inputs {
		loggerFields := inputFields(&input)
		e.instrumentation.startEvaluateInput(ctx, loggerFields)
		allRuleResults := []models.RuleResults{}
		totalResults := 0
		for _, p := range e.policySets {
			ruleResults := p.eval(ctx, &parallelEvalOptions{
				resourcesResolver: options.ResourcesResolver,
				regoOptions: []func(*rego.Rego){
					rego.StrictBuiltinErrors(true),
				},
				input:        &input,
				ruleIDs:      options.RuleIDs,
				workers:      options.Workers,
				loggerFields: loggerFields,
			})
			allRuleResults = append(allRuleResults, ruleResults...)
			for _, r := range ruleResults {
				totalResults += len(r.Results)
			}
		}
		// Ensure deterministic output.
		sort.Slice(allRuleResults, func(i, j int) bool {
			return allRuleResults[i].Package_ < allRuleResults[j].Package_
		})
		results = append(results, models.Result{
			Input:       input,
			RuleResults: allRuleResults,
		})
		loggerFields = append(loggerFields,
			withField("policies", len(allRuleResults)),
			withField("results", totalResults),
		)
		e.instrumentation.finishEvaluateInput(ctx, loggerFields)
	}

	ruleSets := make([]models.RuleSet, len(e.policySets))
	for idx, p := range e.policySets {
		ruleSets[idx] = *p.toRuleSet()
	}
	e.instrumentation.finishEvaluate(ctx)
	var errors []string
	for _, err := range e.errors {
		errors = append(errors, err.Error())
	}

	return &models.Results{
		Format:        "results",
		FormatVersion: "1.1.0",
		Results:       results,
		RuleSets:      ruleSets,
		Errors:        errors,
	}
}

type MetadataResult struct {
	Package  string          `json:"package"`
	Metadata policy.Metadata `json:"metadata"`
	Error    string          `json:"error,omitempty"`
}

// Metadata returns the metadata of all Policies that have been loaded into this
// Engine instance.
func (e *Engine) Metadata(ctx context.Context) []MetadataResult {
	metadata := []MetadataResult{}
	for _, p := range e.policySets {
		m := p.metadata(ctx, []func(*rego.Rego){
			rego.StrictBuiltinErrors(true),
		})
		metadata = append(metadata, m...)
	}
	// Ensure a consistent ordering for policies to make our output
	// deterministic.
	sort.Slice(metadata, func(i, j int) bool {
		return metadata[i].Package < metadata[j].Package
	})

	return metadata
}

type engineInstrumentation struct {
	instrumentation
}

func (i *engineInstrumentation) startInitialization(ctx context.Context) {
	i.startPhase(ctx, "initialize_engine")
}

func (i *engineInstrumentation) finishInitialization(ctx context.Context) {
	i.finishPhase(ctx, "initialize_engine")
}

func (i *engineInstrumentation) startInitializePolicySets(ctx context.Context) {
	i.startPhase(ctx, "initialize_policy_sets")
}

func (i *engineInstrumentation) finishInitializePolicySets(ctx context.Context) {
	i.finishPhase(ctx, "initialize_policy_sets")
}

func (i *engineInstrumentation) startEvaluate(ctx context.Context) {
	i.startPhase(ctx, "evaluate_all_inputs")
}

func (i *engineInstrumentation) finishEvaluate(ctx context.Context) {
	i.finishPhase(ctx, "evaluate_all_inputs")
}

func (i *engineInstrumentation) startEvaluateInput(ctx context.Context, fields []loggerOption) {
	i.startPhase(ctx, "evaluate_inputs", fields...)
}

func (i *engineInstrumentation) finishEvaluateInput(ctx context.Context, fields []loggerOption) {
	i.finishPhase(ctx, "evaluate_inputs", fields...)
}

func inputFields(input *models.State) []loggerOption {
	resourceTypes := len(input.Resources)
	resources := 0
	for _, rt := range input.Resources {
		resources += len(rt)
	}
	return []loggerOption{
		withField("input_type", input.InputType),
		withField("scope", input.Scope),
		withField("resource_types", resourceTypes),
		withField("resources", resources),
	}
}

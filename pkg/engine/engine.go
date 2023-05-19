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

package engine

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/snyk/policy-engine/pkg/bundle"
	"github.com/snyk/policy-engine/pkg/bundle/base"
	"github.com/snyk/policy-engine/pkg/data"
	"github.com/snyk/policy-engine/pkg/internal/withtimeout"
	"github.com/snyk/policy-engine/pkg/logging"
	"github.com/snyk/policy-engine/pkg/metrics"
	"github.com/snyk/policy-engine/pkg/models"
	"github.com/snyk/policy-engine/pkg/policy"
)

const (
	DefaultInitTimeout  = 30 * time.Second
	DefaultEvalTimeout  = 5 * time.Minute
	DefaultQueryTimeout = 45 * time.Second
)

// Engine is responsible for evaluating some States with a given set of rules.
type Engine struct {
	// InitializationErrors contains any errors that occurred during initialization.
	InitializationErrors []error
	instrumentation      *engineInstrumentation
	policySets           []*policySet
	timeouts             Timeouts
}

type Timeouts struct {
	// Init sets the maximum duration that the engine can take to initialize.
	// This timeout is applied per bundle or policy set.
	Init time.Duration

	// Eval sets the maximum duration that the engine can take to evaluate an
	// input. This timeout is applied per bundle or policy set.
	Eval time.Duration

	// Query sets the maximum duration that the engine can take to evaluate any
	// single query. This timeout is applied while evaluating individual
	// policies, querying metadata, or running ad-hoc queries.
	Query time.Duration
}

func (t Timeouts) withDefaults() Timeouts {
	new := Timeouts{
		Init:  t.Init,
		Eval:  t.Eval,
		Query: t.Query,
	}
	if new.Init < 1 {
		new.Init = DefaultInitTimeout
	}
	if new.Eval < 1 {
		new.Eval = DefaultEvalTimeout
	}
	if new.Query < 1 {
		new.Query = DefaultQueryTimeout
	}
	return new
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

	// Timeouts controls timeouts for different engine operations.
	Timeouts Timeouts
}

// NewEngine constructs a new Engine instance.
func NewEngine(ctx context.Context, options *EngineOptions) *Engine {
	logger := options.Logger
	if logger == nil {
		logger = logging.NopLogger
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
		timeouts: options.Timeouts.withDefaults(),
	}
	eng.instrumentation.startInitialization(ctx, eng)
	eng.initPolicySets(ctx, options.Providers, options.BundleReaders)
	eng.instrumentation.finishInitialization(ctx, eng)
	return eng
}

func (e *Engine) initPolicySets(ctx context.Context, providers []data.Provider, readers []bundle.Reader) {
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
			timeouts: e.timeouts,
		})
		if err != nil {
			e.InitializationErrors = append(e.InitializationErrors, err)
		} else {
			e.policySets = append(e.policySets, policySet)
		}
	}

	for _, r := range readers {
		sourceInfo := r.Info()
		var policySource PolicySource
		if sourceInfo.SourceType == bundle.ARCHIVE {
			policySource = POLICY_SOURCE_BUNDLE_ARCHIVE
		} else if sourceInfo.SourceType == bundle.DIRECTORY {
			policySource = POLICY_SOURCE_BUNDLE_DIRECTORY
		}
		b, err := bundle.ReadBundle(r)
		if err != nil {
			e.InitializationErrors = append(e.InitializationErrors,
				newRuleBundleError(
					models.RuleBundle{
						Name:     sourceInfo.FileInfo.Path,
						Source:   string(policySource),
						Checksum: sourceInfo.FileInfo.Checksum,
					},
					fmt.Errorf("%w: %v", ErrFailedToReadBundle, err),
				))
			continue
		}
		policySet, err := newPolicySet(ctx, policySetOptions{
			providers: []data.Provider{b.Provider()},
			source:    policySource,
			name:      sourceInfo.FileInfo.Path,
			checksum:  sourceInfo.FileInfo.Checksum,
			instrumentation: e.instrumentation.policySetInstrumentation(
				string(policySource),
				sourceInfo,
			),
			timeouts: e.timeouts,
		})
		if err != nil {
			e.InitializationErrors = append(e.InitializationErrors, err)
			continue
		}
		e.policySets = append(e.policySets, policySet)
	}
	e.instrumentation.finishInitializePolicySets(ctx)
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
	ruleBundleErrors := map[models.RuleBundle][]string{}
	for _, input := range options.Inputs {
		loggerFields := inputFields(&input)
		e.instrumentation.startEvaluateInput(ctx, loggerFields)
		allRuleResults := []models.RuleResults{}
		totalResults := 0
		for _, p := range e.policySets {
			err := withtimeout.Do(ctx, e.timeouts.Eval, ErrEvalTimedOut, func(ctx context.Context) error {
				ruleResults, err := p.eval(ctx, &parallelEvalOptions{
					resourcesResolver: options.ResourcesResolver,
					input:             &input,
					ruleIDs:           options.RuleIDs,
					workers:           options.Workers,
					loggerFields:      loggerFields,
				})
				if err != nil {
					return err
				}
				allRuleResults = append(allRuleResults, ruleResults...)
				for _, r := range ruleResults {
					totalResults += len(r.Results)
				}
				return nil
			})
			if err != nil {
				bundle := p.ruleBundle()
				ruleBundleErrors[bundle] = append(ruleBundleErrors[bundle], err.Error())
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

	e.instrumentation.finishEvaluate(ctx)
	ruleBundles := []models.RuleBundleInfo{}
	for _, p := range e.policySets {
		bundle := p.ruleBundle()
		ruleBundles = append(ruleBundles, models.RuleBundleInfo{
			RuleBundle: &bundle,
			Errors:     ruleBundleErrors[bundle],
		})
	}
	for _, err := range e.InitializationErrors {
		if err, ok := err.(*RuleBundleError); ok {
			ruleBundles = append(ruleBundles, err.ToModel())
		}
	}

	return &models.Results{
		Format:        "results",
		FormatVersion: "1.2.0",
		Results:       results,
		RuleBundles:   ruleBundles,
	}
}

type MetadataResult struct {
	Package  string          `json:"package"`
	Metadata policy.Metadata `json:"metadata"`
	Error    string          `json:"error,omitempty"`
}

// Metadata returns the metadata of all Policies that have been loaded into this
// Engine instance.
func (e *Engine) Metadata(ctx context.Context) ([]MetadataResult, error) {
	metadata := []MetadataResult{}
	for _, p := range e.policySets {
		m, err := p.metadata(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to query metadata: %w", err)
		}
		metadata = append(metadata, m...)
	}
	// Ensure a consistent ordering for policies to make our output
	// deterministic.
	sort.Slice(metadata, func(i, j int) bool {
		return metadata[i].Package < metadata[j].Package
	})

	return metadata, nil
}

// Query runs the given query against all policy sets and invokes the result
// processor on each result.
func (e *Engine) Query(ctx context.Context, options *QueryOptions) error {
	for _, p := range e.policySets {
		err := p.query(ctx, options)
		if err != nil {
			return err
		}
	}
	return nil
}

type engineInstrumentation struct {
	instrumentation
}

func (i *engineInstrumentation) startInitialization(ctx context.Context, eng *Engine) {
	i.startPhase(ctx, "initialize_engine",
		withField("init_timeout", eng.timeouts.Init),
		withField("eval_timeout", eng.timeouts.Eval),
		withField("query_timeout", eng.timeouts.Query))
}

func (i *engineInstrumentation) finishInitialization(ctx context.Context, eng *Engine) {
	i.finishPhase(ctx, "initialize_engine",
		withField("policy_sets", len(eng.policySets)),
		withField("errors", len(eng.InitializationErrors)),
	)
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

func (i *engineInstrumentation) policySetInstrumentation(policySource string, sourceInfo base.SourceInfo) instrumentation {
	labels := metrics.Labels{
		"policy_set_source": policySource,
		"policy_set_name":   sourceInfo.FileInfo.Path,
	}
	fields := []loggerOption{
		withField("policy_set_source", policySource),
		withField("policy_set_name", sourceInfo.FileInfo.Path),
	}
	if sourceInfo.FileInfo.Checksum != "" {
		labels["policy_set_checksum"] = sourceInfo.FileInfo.Checksum
		fields = append(fields, withField("policy_set_checksum", sourceInfo.FileInfo.Checksum))
	}
	return i.child(
		labels,
		info,
		fields...,
	)
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

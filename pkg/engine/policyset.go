// © 2023 Snyk Limited All rights reserved.
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
	"runtime"
	"sort"
	"sync"

	"github.com/hashicorp/go-multierror"
	"github.com/open-policy-agent/opa/ast"
	"github.com/snyk/policy-engine/pkg/data"
	"github.com/snyk/policy-engine/pkg/internal/withtimeout"
	"github.com/snyk/policy-engine/pkg/metrics"
	"github.com/snyk/policy-engine/pkg/models"
	"github.com/snyk/policy-engine/pkg/policy"
	"github.com/snyk/policy-engine/pkg/rego"
)

type PolicySource string

const (
	POLICY_SOURCE_DATA             PolicySource = "data"
	POLICY_SOURCE_BUNDLE_ARCHIVE   PolicySource = "bundle_archive"
	POLICY_SOURCE_BUNDLE_DIRECTORY PolicySource = "bundle_directory"
)

type policySet struct {
	PolicyConsumer
	instrumentation *policySetInstrumentation
	rego            *rego.State
	policies        []policy.Policy
	name            string
	source          PolicySource
	checksum        string
	timeouts        Timeouts
}

type policySetOptions struct {
	providers       []data.Provider
	source          PolicySource
	instrumentation instrumentation
	name            string
	checksum        string
	timeouts        Timeouts
}

type RuleBundleError struct {
	ruleBundle *models.RuleBundle
	err        error
}

func (p *RuleBundleError) Error() string {
	return p.err.Error()
}

func (p *RuleBundleError) ToModel() models.RuleBundleInfo {
	return models.RuleBundleInfo{
		RuleBundle: p.ruleBundle,
		Errors:     []string{p.Error()},
	}
}

func newRuleBundleError(ruleBundle models.RuleBundle, err error) error {
	return &RuleBundleError{
		ruleBundle: &ruleBundle,
		err:        err,
	}
}

func newPolicySet(ctx context.Context, options policySetOptions) (*policySet, error) {
	s := &policySet{
		instrumentation: &policySetInstrumentation{
			instrumentation: options.instrumentation,
		},
		PolicyConsumer: *NewPolicyConsumer(),
		name:           options.name,
		source:         options.source,
		checksum:       options.checksum,
		timeouts:       options.timeouts,
	}
	s.instrumentation.startInitialization(ctx)
	defer s.instrumentation.finishInitialization(ctx, s)

	err := withtimeout.Do(ctx, options.timeouts.Init, ErrInitTimedOut, func(ctx context.Context) error {
		if err := s.loadRegoAPI(ctx); err != nil {
			return fmt.Errorf("%w: %v", FailedToLoadRegoAPI, err)
		}
		if err := s.consumeProviders(ctx, options.providers); err != nil {
			return fmt.Errorf("%w: %v", FailedToLoadRules, err)
		}
		s.extractPolicies(ctx)
		if err := s.compile(ctx); err != nil {
			return fmt.Errorf("%w: %v", FailedToCompile, err)
		}
		return nil
	})

	if err != nil {
		return nil, newRuleBundleError(s.ruleBundle(), err)
	}

	return s, nil
}

func (s *policySet) loadRegoAPI(ctx context.Context) error {
	s.instrumentation.startLoadRegoAPI(ctx)
	defer s.instrumentation.finishLoadRegoAPI(ctx)
	if err := policy.RegoAPIProvider(ctx, s); err != nil {
		return err
	}
	return data.PureRegoLibProvider()(ctx, s)
}

func (s *policySet) consumeProviders(ctx context.Context, providers []data.Provider) error {
	s.instrumentation.startConsumeProviders(ctx)
	defer s.instrumentation.finishConsumeProviders(ctx)
	var result *multierror.Error
	for _, p := range providers {
		if err := p(ctx, s); err != nil {
			result = multierror.Append(result, err)
		}
	}
	return result.ErrorOrNil()
}

func (s *policySet) extractPolicies(ctx context.Context) {
	s.instrumentation.startExtractPolicies(ctx)
	defer s.instrumentation.finishExtractPolicies(ctx)
	tree := ast.NewModuleTree(s.Modules)
	policies := []policy.Policy{}
	for _, moduleSet := range policy.ExtractModuleSets(tree) {
		p, err := policy.PolicyFactory(moduleSet)
		if err != nil {
			// This can happen if customers include non-rule code in the rules
			// package, so we just log a warning.
			s.instrumentation.extractPoliciesError(ctx, err)
		} else if p != nil {
			policies = append(policies, p)
		}
	}
	s.policies = policies
}

func (s *policySet) compile(ctx context.Context) error {
	s.instrumentation.startCompile(ctx)
	defer s.instrumentation.finishCompile(ctx)
	var err error
	s.rego, err = rego.NewState(rego.Options{
		Modules:      s.Modules,
		Document:     s.Document,
		Capabilities: policy.Capabilities(),
	})
	if err != nil {
		return err
	}
	return nil
}

type evalPolicyOptions struct {
	resourcesResolver policy.ResourcesResolver
	policy            policy.Policy
	input             *models.State
	relationsCache    *policy.RelationsCache
}

func (s *policySet) evalPolicy(ctx context.Context, options *evalPolicyOptions) policyResults {
	pol := options.policy
	instrumentation := s.instrumentation.policyEvalInstrumentation(pol)
	instrumentation.startEval(ctx)

	ruleResults, err := pol.Eval(ctx, policy.EvalOptions{
		RegoState:         s.rego,
		Logger:            instrumentation.logger,
		ResourcesResolver: options.resourcesResolver,
		Input:             options.input,
		RelationsCache:    options.relationsCache,
		Timeout:           s.timeouts.Query,
	})
	totalResults := 0
	for idx, r := range ruleResults {
		bundle := s.ruleBundle()
		ruleResults[idx].RuleBundle = &bundle
		totalResults += len(r.Results)
	}
	instrumentation.finishEval(ctx, totalResults)
	// We always want to return results, because that's how policy-level errors
	// are communicated into the output right now.
	return policyResults{
		ruleResults: ruleResults,
		err:         err,
	}
}

type policyFilter func(ctx context.Context, pol policy.Policy) (bool, error)

func (s *policySet) selectPolicies(ctx context.Context, filters []policyFilter) ([]policy.Policy, error) {
	s.instrumentation.startPolicySelection(ctx)
	var subset []policy.Policy
	err := withtimeout.Do(ctx, s.timeouts.Query, ErrQueryTimedOut, func(ctx context.Context) error {
		for _, pol := range s.policies {
			include := true
			for _, filter := range filters {
				matches, err := filter(ctx, pol)
				if err != nil {
					return err
				}
				if !matches {
					include = false
					break
				}
			}
			if include {
				subset = append(subset, pol)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err

	}
	s.instrumentation.finishPolicySelection(ctx, len(subset))
	return subset, nil
}

func (s *policySet) ruleIDFilter(ruleIDs []string) policyFilter {
	ids := map[string]bool{}
	for _, r := range ruleIDs {
		ids[r] = true
	}
	return func(ctx context.Context, pol policy.Policy) (bool, error) {
		id, err := pol.ID(ctx, s.rego)
		if err != nil {
			s.instrumentation.policyIDError(ctx, pol.Package(), err)
			return false, err
		}
		return ids[id], nil
	}
}

type parallelEvalOptions struct {
	resourcesResolver policy.ResourcesResolver
	workers           int
	input             *models.State
	ruleIDs           []string
	loggerFields      []loggerOption
}

func (s *policySet) eval(ctx context.Context, options *parallelEvalOptions) ([]models.RuleResults, error) {
	// Get list of policies to evaluate

	filters := []policyFilter{
		func(_ context.Context, pol policy.Policy) (bool, error) {
			return pol.InputTypeMatches(options.input.InputType), nil
		},
	}
	if len(options.ruleIDs) > 0 {
		filters = append(filters, s.ruleIDFilter(options.ruleIDs))
	}
	policies, err := s.selectPolicies(ctx, filters)
	if err != nil {
		return nil, newRuleBundleError(
			s.ruleBundle(),
			fmt.Errorf("error during policy selection: %w", err),
		)
	}

	// Precompute relations
	relationsCache, err := s.precomputeRelationsCache(ctx, options.input, options.resourcesResolver)
	if err != nil {
		return nil, newRuleBundleError(
			s.ruleBundle(),
			fmt.Errorf("error querying relations: %w", err),
		)
	}

	// Spin off N workers to go through the list

	numWorkers := options.workers
	if numWorkers < 1 {
		numWorkers = runtime.NumCPU() + 1
	}
	loggerFields := []loggerOption{withField("workers", numWorkers)}
	loggerFields = append(loggerFields, options.loggerFields...)
	s.instrumentation.startEval(ctx, loggerFields)
	defer s.instrumentation.finishEval(ctx, loggerFields)
	allRuleResults := []models.RuleResults{}
	policyChan := make(chan policy.Policy)
	resultsChan := make(chan policyResults)
	var wg sync.WaitGroup
	go func() {
		for i := 0; i < numWorkers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					p, ok := <-policyChan
					if !ok {
						return
					}
					resultsChan <- s.evalPolicy(ctx, &evalPolicyOptions{
						resourcesResolver: options.resourcesResolver,
						policy:            p,
						input:             options.input,
						relationsCache:    relationsCache,
					})
				}
			}()
		}
		for _, p := range policies {
			policyChan <- p
		}
		close(policyChan)
		wg.Wait()
		close(resultsChan)
	}()
	for {
		policyResults, ok := <-resultsChan
		if !ok {
			break
		}
		s.instrumentation.countPolicyEval(ctx)
		// TODO: how do errors get out of here?
		if policyResults.err != nil {
			s.instrumentation.countPolicyEvalError(ctx)
		}
		allRuleResults = append(allRuleResults, policyResults.ruleResults...)
	}

	return allRuleResults, nil
}

func (s *policySet) precomputeRelationsCache(
	ctx context.Context,
	input *models.State,
	resourcesResolver policy.ResourcesResolver,
) (*policy.RelationsCache, error) {
	s.instrumentation.startPrecomputeRelations(ctx)
	defer s.instrumentation.finishPrecomputeRelations(ctx)
	relationsCache := policy.RelationsCache{}

	found := false
	err := s.query(
		ctx,
		&QueryOptions{
			Query:             "data.snyk.internal.relations.forward",
			Input:             input,
			ResourcesResolver: resourcesResolver,
			ResultProcessor: func(val ast.Value) error {
				relationsCache.Forward = val
				found = true
				return nil
			},
		},
	)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("foward relations cache was not found")
	}

	found = false
	err = s.query(
		ctx,
		&QueryOptions{
			Query:             "data.snyk.internal.relations.backward",
			Input:             input,
			ResourcesResolver: resourcesResolver,
			ResultProcessor: func(val ast.Value) error {
				relationsCache.Backward = val
				found = true
				return nil
			},
		},
	)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("foward relations cache was not found")
	}

	return &relationsCache, nil
}

func (s *policySet) metadata(ctx context.Context) ([]MetadataResult, error) {
	// Ensure a consistent ordering for policies to make our output
	// deterministic.
	policies := make([]policy.Policy, len(s.policies))
	copy(policies, s.policies)
	sort.Slice(policies, func(i, j int) bool {
		return policies[i].Package() < policies[j].Package()
	})
	metadata := make([]MetadataResult, len(policies))
	err := withtimeout.Do(ctx, s.timeouts.Query, ErrQueryTimedOut, func(ctx context.Context) error {
		for idx, p := range policies {
			m, err := p.Metadata(ctx, s.rego)
			result := MetadataResult{
				Package: p.Package(),
			}
			if err != nil {
				result.Error = err.Error()
			} else {
				result.Metadata = m
			}
			metadata[idx] = result
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return metadata, nil
}

// QueryOptions contain options for Engine.Query
type QueryOptions struct {
	// Query is a rego query
	Query string
	// Input is an optional state to query against
	Input *models.State
	// ResourceResolver is an optional function that returns a resource state
	// for the given ResourceRequest. Multiple ResourcesResolvers can be
	// composed with And() and Or().
	ResourcesResolver policy.ResourcesResolver
	// ResultProcessor is a function that is run on every result returned by the
	// query.
	ResultProcessor func(ast.Value) error
}

func (s *policySet) query(ctx context.Context, options *QueryOptions) error {
	input := options.Input
	if input == nil {
		input = &models.State{}
	}
	builtins := policy.NewBuiltins(input, options.ResourcesResolver, nil)
	return s.rego.Query(ctx, rego.Query{
		Query:    options.Query,
		Builtins: builtins.Implementations(),
		// TODO: remove once we're no longer looking at input.resources in
		// Snyk rules
		Input: ast.NewObject(
			[2]*ast.Term{ast.StringTerm("resources"), ast.ObjectTerm()},
		),
		Timeout: s.timeouts.Query,
	}, options.ResultProcessor)
}

func (s *policySet) ruleBundle() models.RuleBundle {
	return models.RuleBundle{
		Name:     s.name,
		Source:   string(s.source),
		Checksum: s.checksum,
	}
}

type policySetInstrumentation struct {
	instrumentation
}

func (i *policySetInstrumentation) startInitialization(ctx context.Context) {
	i.startPhase(ctx, "initialize_policy_set")
}

func (i *policySetInstrumentation) finishInitialization(ctx context.Context, s *policySet) {
	modules := len(s.Modules)
	docs := s.NumDocuments
	policies := len(s.policies)
	i.finishPhase(ctx, "initialize_policy_set",
		withField("modules_loaded", modules),
		withField("data_documents_loaded", docs),
		withField("policies_loaded", policies),
	)
}

func (i *policySetInstrumentation) startLoadRegoAPI(ctx context.Context) {
	i.startPhase(ctx, "load_rego_api")
}

func (i *policySetInstrumentation) finishLoadRegoAPI(ctx context.Context) {
	i.finishPhase(ctx, "load_rego_api")
}

func (i *policySetInstrumentation) startConsumeProviders(ctx context.Context) {
	i.startPhase(ctx, "consume_providers")
}

func (i *policySetInstrumentation) finishConsumeProviders(ctx context.Context) {
	i.finishPhase(ctx, "consume_providers")
}

func (i *policySetInstrumentation) startExtractPolicies(ctx context.Context) {
	i.startPhase(ctx, "extract_policies")
}

func (i *policySetInstrumentation) finishExtractPolicies(ctx context.Context) {
	i.finishPhase(ctx, "extract_policies")
}

func (i *policySetInstrumentation) extractPoliciesError(ctx context.Context, err error) {
	// Using WithField here because we don't want a stack trace in this situation
	i.logger.
		WithField("error", err.Error()).
		Warn(ctx, "Error while parsing policy. It will still be loaded and accessible via data.")
}

func (i *policySetInstrumentation) startCompile(ctx context.Context) {
	i.startPhase(ctx, "compile")
}

func (i *policySetInstrumentation) finishCompile(ctx context.Context) {
	i.finishPhase(ctx, "compile")
}

func (i *policySetInstrumentation) startPolicySelection(ctx context.Context) {
	i.startPhase(ctx, "policy_selection")
}

func (i *policySetInstrumentation) finishPolicySelection(ctx context.Context, policies int) {
	i.finishPhase(ctx, "policy_selection",
		withField("policies", policies),
	)
}

func (i *policySetInstrumentation) policyIDError(ctx context.Context, pkg string, err error) {
	i.logger.
		WithField("package", pkg).
		WithError(err).
		Error(ctx, "failed to extract rule ID")
}

func (i *policySetInstrumentation) startPrecomputeRelations(ctx context.Context) {
	i.startPhase(ctx, "precompute_relations")
}

func (i *policySetInstrumentation) finishPrecomputeRelations(ctx context.Context) {
	i.finishPhase(ctx, "precompute_relations")
}

func (i *policySetInstrumentation) startEval(ctx context.Context, fields []loggerOption) {
	i.startPhase(ctx, "evaluate_policy_set", fields...)
}

func (i *policySetInstrumentation) finishEval(ctx context.Context, fields []loggerOption) {
	i.finishPhase(ctx, "evaluate_policy_set", fields...)
}

func (i *policySetInstrumentation) countPolicyEval(ctx context.Context) {
	i.metrics.
		Counter(ctx, "policies_evaluated", "", i.labels).
		Inc()
}

func (i *policySetInstrumentation) countPolicyEvalError(ctx context.Context) {
	i.metrics.
		Counter(ctx, "policy_evaluation_errors", "", i.labels).
		Inc()
}

func (i *policySetInstrumentation) policyEvalInstrumentation(p policy.Policy) *policyEvalInstrumentation {
	pkg := p.Package()
	return &policyEvalInstrumentation{
		instrumentation: i.child(
			metrics.Labels{"package": pkg},
			debug,
			withField("package", pkg),
		),
	}
}

type policyEvalInstrumentation struct {
	instrumentation
}

func (i *policyEvalInstrumentation) startEval(ctx context.Context) {
	i.startPhase(ctx, "evaluate_policy")
}

func (i *policyEvalInstrumentation) finishEval(ctx context.Context, results int) {
	i.finishPhase(ctx, "evaluate_policy",
		withField("results", results),
	)
}

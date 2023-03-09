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
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/storage/inmem"
	"github.com/snyk/policy-engine/pkg/data"
	"github.com/snyk/policy-engine/pkg/metrics"
	"github.com/snyk/policy-engine/pkg/models"
	"github.com/snyk/policy-engine/pkg/policy"
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
	compiler        *ast.Compiler
	store           storage.Store
	policies        []policy.Policy
	name            string
	source          PolicySource
	checksum        string
}

type policySetOptions struct {
	providers       []data.Provider
	source          PolicySource
	instrumentation instrumentation
	name            string
	checksum        string
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

func newRuleBundleError(ruleBundle *models.RuleBundle, err error) error {
	return &RuleBundleError{
		ruleBundle: ruleBundle,
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
	}
	s.instrumentation.startInitialization(ctx)
	defer s.instrumentation.finishInitialization(ctx, s)
	if err := s.loadRegoAPI(ctx); err != nil {
		return nil, newRuleBundleError(s.ruleBundle(), fmt.Errorf("%w: %v", FailedToLoadRegoAPI, err))
	}
	if err := s.consumeProviders(ctx, options.providers); err != nil {
		return nil, newRuleBundleError(s.ruleBundle(), fmt.Errorf("%w: %v", FailedToLoadRules, err))
	}
	s.extractPolicies(ctx)
	if err := s.compile(ctx); err != nil {
		return nil, newRuleBundleError(s.ruleBundle(), fmt.Errorf("%w: %v", FailedToCompile, err))
	}
	s.initStore(ctx)
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
	s.compiler = ast.NewCompiler().WithCapabilities(policy.Capabilities())
	s.compiler.Compile(s.Modules)
	if len(s.compiler.Errors) > 0 {
		return s.compiler.Errors
	}
	return nil
}

func (s *policySet) initStore(ctx context.Context) {
	s.instrumentation.startInitStore(ctx)
	defer s.instrumentation.finishInitStore(ctx)
	s.store = inmem.NewFromObject(s.Document)
}

func (s *policySet) regoOptions(base []func(*rego.Rego)) []func(*rego.Rego) {
	regoOptions := []func(*rego.Rego){
		rego.Compiler(s.compiler),
		rego.Store(s.store),
	}
	return append(regoOptions, base...)
}

type evalPolicyOptions struct {
	resourcesResolver policy.ResourcesResolver
	policy            policy.Policy
	regoOptions       []func(*rego.Rego)
	input             *models.State
}

func (s *policySet) evalPolicy(ctx context.Context, options *evalPolicyOptions) policyResults {
	pol := options.policy
	instrumentation := s.instrumentation.policyEvalInstrumentation(pol)
	instrumentation.startEval(ctx)
	ruleResults, err := pol.Eval(ctx, policy.EvalOptions{
		RegoOptions:       s.regoOptions(options.regoOptions),
		Logger:            instrumentation.logger,
		ResourcesResolver: options.resourcesResolver,
		Input:             options.input,
	})
	totalResults := 0
	for idx, r := range ruleResults {
		ruleResults[idx].RuleBundle = s.ruleBundle()
		totalResults += len(r.Results)
	}
	instrumentation.finishEval(ctx, totalResults)
	return policyResults{
		ruleResults: ruleResults,
		err:         err,
	}
}

type policyFilter func(pol policy.Policy) bool

func (s *policySet) selectPolicies(ctx context.Context, filters []policyFilter) []policy.Policy {
	s.instrumentation.startPolicySelection(ctx)
	subset := []policy.Policy{}
	for _, pol := range s.policies {
		matches := true
		for _, filter := range filters {
			if !filter(pol) {
				matches = false
			}
		}
		if matches {
			subset = append(subset, pol)
		}
	}
	s.instrumentation.finishPolicySelection(ctx, len(subset))
	return subset
}

func (s *policySet) ruleIDFilter(ctx context.Context, ruleIDs []string, baseOptions []func(*rego.Rego)) policyFilter {
	ids := map[string]bool{}
	for _, r := range ruleIDs {
		ids[r] = true
	}
	regoOptions := s.regoOptions(baseOptions)
	return func(pol policy.Policy) bool {
		id, err := pol.ID(ctx, regoOptions)
		if err != nil {
			s.instrumentation.policyIDError(ctx, pol.Package(), err)
			return false
		}
		return ids[id]
	}
}

type parallelEvalOptions struct {
	resourcesResolver policy.ResourcesResolver
	regoOptions       []func(*rego.Rego)
	workers           int
	input             *models.State
	ruleIDs           []string
	loggerFields      []loggerOption
}

func (s *policySet) eval(ctx context.Context, options *parallelEvalOptions) []models.RuleResults {
	// Get list of policies to evaluate

	filters := []policyFilter{
		func(pol policy.Policy) bool {
			return pol.InputTypeMatches(options.input.InputType)
		},
	}
	if len(options.ruleIDs) > 0 {
		filters = append(filters, s.ruleIDFilter(ctx, options.ruleIDs, options.regoOptions))
	}
	policies := s.selectPolicies(ctx, filters)

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
						regoOptions:       options.regoOptions,
						resourcesResolver: options.resourcesResolver,
						policy:            p,
						input:             options.input,
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
		if policyResults.err != nil {
			s.instrumentation.countPolicyEvalError(ctx)
		}
		allRuleResults = append(allRuleResults, policyResults.ruleResults...)
	}

	return allRuleResults
}

func (s *policySet) metadata(ctx context.Context, baseOptions []func(*rego.Rego)) []MetadataResult {
	regoOptions := s.regoOptions(baseOptions)
	// Ensure a consistent ordering for policies to make our output
	// deterministic.
	policies := make([]policy.Policy, len(s.policies))
	copy(policies, s.policies)
	sort.Slice(policies, func(i, j int) bool {
		return policies[i].Package() < policies[j].Package()
	})
	metadata := make([]MetadataResult, len(policies))
	for idx, p := range policies {
		m, err := p.Metadata(ctx, regoOptions)
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
	return metadata
}

func (s *policySet) ruleBundle() *models.RuleBundle {
	return &models.RuleBundle{
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

func (i *policySetInstrumentation) startInitStore(ctx context.Context) {
	i.startPhase(ctx, "init_store")
}

func (i *policySetInstrumentation) finishInitStore(ctx context.Context) {
	i.finishPhase(ctx, "init_store")
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

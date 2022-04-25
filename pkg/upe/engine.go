package upe

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/storage/inmem"
	"github.com/snyk/unified-policy-engine/pkg/data"
	"github.com/snyk/unified-policy-engine/pkg/logging"
	"github.com/snyk/unified-policy-engine/pkg/metrics"
	"github.com/snyk/unified-policy-engine/pkg/models"
	"github.com/snyk/unified-policy-engine/pkg/policy"
)

type Engine struct {
	policies    []policy.Policy
	compiler    *ast.Compiler
	store       storage.Store
	ruleIDs     map[string]bool
	runAllRules bool
}

type EngineOptions struct {
	Providers []data.Provider
	RuleIDs   map[string]bool
	Logger    logging.Logger
	Metrics   metrics.Metrics
}

func NewEngine(ctx context.Context, options *EngineOptions) (*Engine, error) {
	logger := options.Logger
	if logger == nil {
		logger = logging.DefaultLogger
	}
	m := options.Metrics
	logger.Info(ctx, "Initializing engine")
	consumer := NewPolicyConsumer()
	if err := policy.RegoAPIProvider(ctx, consumer); err != nil {
		logger.Error(ctx, "Failed to load rego API")
		return nil, err
	}
	providersStart := time.Now()
	for _, p := range options.Providers {
		if err := p(ctx, consumer); err != nil {
			logger.Error(ctx, "Failed to consume rule and data providers")
			return nil, err
		}
	}
	m.Timer(ctx, metrics.PROVIDERS_LOAD_TIME, "", metrics.Labels{}).
		Record(time.Now().Sub(providersStart))
	logger.WithField(logging.MODULES, len(consumer.Modules)).
		WithField(logging.DATA_DOCUMENTS, len(consumer.Documents)).
		Info(ctx, "Finished consuming providers")
	compiler := ast.NewCompiler().WithCapabilities(policy.Capabilities())
	compilationStart := time.Now()
	compiler.Compile(consumer.Modules)
	m.Timer(ctx, metrics.COMPILATION_TIME, "", metrics.Labels{}).
		Record(time.Now().Sub(compilationStart))
	if len(compiler.Errors) > 0 {
		err := compiler.Errors.Error()
		logger.Error(ctx, "Failed during compilation")
		return nil, fmt.Errorf(err)
	}
	logger.Info(ctx, "Finished initializing engine")
	m.Counter(ctx, metrics.MODULES_LOADED, "", metrics.Labels{}).
		Add(float64(len(consumer.Modules)))
	m.Counter(ctx, metrics.DATA_DOCUMENTS_LOADED, "", metrics.Labels{}).
		Add(float64(len(consumer.Documents)))
	m.Counter(ctx, metrics.POLICIES_LOADED, "", metrics.Labels{}).
		Add(float64(len(consumer.Policies)))
	return &Engine{
		compiler:    compiler,
		policies:    consumer.Policies,
		store:       inmem.NewFromObject(consumer.Documents),
		ruleIDs:     options.RuleIDs,
		runAllRules: len(options.RuleIDs) < 1,
	}, nil
}

type policyResults struct {
	pkg         string
	err         error
	ruleResults models.RuleResults
}

type EvalOptions struct {
	Inputs  []models.State
	Logger  logging.Logger
	Metrics metrics.Metrics
}

func (e *Engine) Eval(ctx context.Context, options EvalOptions) (*models.Results, error) {
	logger := options.Logger
	if logger == nil {
		logger = logging.DefaultLogger
	}
	m := options.Metrics
	logger.Debug(ctx, "Beginning evaluation")
	regoOptions := []func(*rego.Rego){
		rego.Compiler(e.compiler),
		rego.Store(e.store),
	}
	policies := e.policies
	if !e.runAllRules {
		ruleSelectionStart := time.Now()
		policies = []policy.Policy{}
		for _, p := range e.policies {
			id, err := p.ID(ctx, regoOptions)
			if err != nil {
				logger.WithField("package", p.Package()).
					Error(ctx, "Failed to extract ID from policy")
				return nil, err
			}
			if !e.ruleIDs[id] {
				continue
			}
			policies = append(policies, p)
		}
		m.Timer(ctx, metrics.RULE_SELECTION_TIME, "", metrics.Labels{}).
			Record(time.Now().Sub(ruleSelectionStart))
	}
	results := []models.Result{}
	for idx, state := range options.Inputs {
		options := policy.EvalOptions{
			RegoOptions: regoOptions,
			Input:       &state,
		}
		allRuleResults := map[string]models.RuleResults{}
		resultsChan := make(chan policyResults)
		var wg sync.WaitGroup
		ruleEvalCounter := m.Counter(ctx, metrics.RULES_EVALUATED, "", metrics.Labels{
			metrics.INPUT_IDX: fmt.Sprint(idx),
		})
		totalEvalStart := time.Now()
		go func() {
			for _, p := range policies {
				if !inputTypeMatches(p.InputType(), state.InputType) {
					continue
				}
				wg.Add(1)
				go func(p policy.Policy) {
					defer wg.Done()
					pkg := p.Package()
					evalStart := time.Now()
					ruleResults, err := p.Eval(ctx, options)
					labels := metrics.Labels{
						metrics.PACKAGE: pkg,
						// TODO: Do we need a better way to identify inputs?
						metrics.INPUT_IDX: fmt.Sprint(idx),
					}
					m.Timer(ctx, metrics.RULE_EVAL_TIME, "", labels).
						Record(time.Now().Sub(evalStart))
					m.Counter(ctx, metrics.RESULTS_PRODUCED, "", labels).
						Add(float64(len(ruleResults.Results)))
					resultsChan <- policyResults{
						pkg:         pkg,
						err:         err,
						ruleResults: *ruleResults,
					}
				}(p)
				ruleEvalCounter.Inc()
			}
			wg.Wait()
			close(resultsChan)
		}()
		errCounter := m.Counter(ctx, metrics.POLICY_ERRORS, "", metrics.Labels{})
		for {
			select {
			case policyResults, ok := <-resultsChan:
				if !ok {
					resultsChan = nil
					break
				}
				if policyResults.err != nil {
					logger.WithField(logging.PACKAGE, policyResults.pkg).
						WithError(policyResults.err).
						Warn(ctx, "Failed to evaluate policy")
					errCounter.Inc()
					allRuleResults[policyResults.pkg] = policyResults.ruleResults
				} else {
					logger.WithField(logging.PACKAGE, policyResults.pkg).
						Debug(ctx, "Completed policy evaluation")
					allRuleResults[policyResults.pkg] = policyResults.ruleResults
				}
			}
			if resultsChan == nil {
				break
			}
		}
		m.Timer(ctx, metrics.TOTAL_RULE_EVAL_TIME, "", metrics.Labels{
			metrics.INPUT_IDX: fmt.Sprint(idx),
		}).Record(time.Now().Sub(totalEvalStart))
		results = append(results, models.Result{
			Input:       state,
			RuleResults: allRuleResults,
		})
	}
	return &models.Results{
		Format:        "results",
		FormatVersion: "1.0.0",
		Results:       results,
	}, nil
}

func inputTypeMatches(t1, t2 string) bool {
	switch t1 {
	case "tf", "tf_runtime", "tf_plan":
		return t2 == "tf" || t2 == "tf_runtime" || t2 == "tf_plan"
	default:
		return t1 == t2
	}
}

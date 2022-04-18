package upe

import (
	"context"
	"fmt"
	"sync"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/storage/inmem"
	"github.com/snyk/unified-policy-engine/pkg/data"
	"github.com/snyk/unified-policy-engine/pkg/logging"
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
}

func NewEngine(ctx context.Context, options *EngineOptions) (*Engine, error) {
	logger := options.Logger
	if logger == nil {
		logger = logging.DefaultLogger
	}
	logger.Info(ctx, "Initializing engine")
	consumer := NewPolicyConsumer()
	if err := policy.RegoAPIProvider(ctx, consumer); err != nil {
		logger.Error(ctx, "Failed to load rego API")
		return nil, err
	}
	for _, p := range options.Providers {
		if err := p(ctx, consumer); err != nil {
			logger.Error(ctx, "Failed to consume rule and data providers")
			return nil, err
		}
	}
	logger.WithField(logging.MODULES, len(consumer.Modules)).
		WithField(logging.DATA_DOCUMENTS, len(consumer.Documents)).
		Info(ctx, "Finished consuming providers")
	compiler := ast.NewCompiler().WithCapabilities(policy.Capabilities())
	compiler.Compile(consumer.Modules)
	if len(compiler.Errors) > 0 {
		err := compiler.Errors.Error()
		logger.Error(ctx, "Failed during compilation")
		return nil, fmt.Errorf(err)
	}
	// TODO: add compilation time
	logger.Info(ctx, "Finished initializing engine")
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
	Inputs []models.State
	Logger logging.Logger
}

func (e *Engine) Eval(ctx context.Context, options EvalOptions) (*models.Results, error) {
	logger := options.Logger
	if logger == nil {
		logger = logging.DefaultLogger
	}
	logger.Debug(ctx, "Beginning evaluation")
	regoOptions := []func(*rego.Rego){
		rego.Compiler(e.compiler),
		rego.Store(e.store),
	}
	policies := e.policies
	if !e.runAllRules {
		policies := []policy.Policy{}
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
	}
	results := []models.Result{}
	for _, state := range options.Inputs {
		options := policy.EvalOptions{
			RegoOptions: regoOptions,
			Input:       &state,
		}
		allRuleResults := map[string]models.RuleResults{}
		resultsChan := make(chan policyResults)
		var wg sync.WaitGroup
		go func() {
			for _, p := range policies {
				if !inputTypeMatches(p.InputType(), state.InputType) {
					continue
				}
				wg.Add(1)
				go func(p policy.Policy) {
					defer wg.Done()
					ruleResults, err := p.Eval(ctx, options)
					resultsChan <- policyResults{
						pkg:         p.Package(),
						err:         err,
						ruleResults: *ruleResults,
					}
				}(p)
			}
			wg.Wait()
			close(resultsChan)
		}()
		for {
			select {
			case policyResults, ok := <-resultsChan:
				if !ok {
					resultsChan = nil
					break
				}
				if policyResults.err != nil {
					logger.WithField("package", policyResults.pkg).
						Error(ctx, "Failed to evaluate policy")
				} else {
					logger.WithField("package", policyResults.pkg).
						Debug(ctx, "Completed policy evaluation")
					allRuleResults[policyResults.pkg] = policyResults.ruleResults
				}
			}
			if resultsChan == nil {
				break
			}
		}
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

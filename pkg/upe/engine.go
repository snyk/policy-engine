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
}

func NewEngine(ctx context.Context, options *EngineOptions) (*Engine, error) {
	consumer := NewPolicyConsumer()
	if err := policy.RegoAPIProvider(ctx, consumer); err != nil {
		return nil, err
	}
	for _, p := range options.Providers {
		if err := p(ctx, consumer); err != nil {
			return nil, err
		}
	}
	compiler := ast.NewCompiler().WithCapabilities(policy.Capabilities())
	compiler.Compile(consumer.Modules)
	if len(compiler.Errors) > 0 {
		return nil, fmt.Errorf(compiler.Errors.Error())
	}
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
	ruleResults models.RuleResults
}

func (e *Engine) Eval(ctx context.Context, states []models.State) (*models.Results, error) {
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
				return nil, err
			}
			if !e.ruleIDs[id] {
				continue
			}
			policies = append(policies, p)
		}
	}
	results := []models.Result{}
	for _, state := range states {
		options := policy.EvalOptions{
			RegoOptions: regoOptions,
			Input:       &state,
		}
		allRuleResults := map[string]models.RuleResults{}
		errors := []error{}
		resultsChan := make(chan policyResults)
		errorChan := make(chan error)
		// waitChan := make(chan struct{})
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
					if err != nil {
						errorChan <- err
					} else {
						resultsChan <- policyResults{
							pkg:         p.Package(),
							ruleResults: *ruleResults,
						}
					}
				}(p)
			}
			wg.Wait()
			close(resultsChan)
			close(errorChan)
		}()
		for {
			select {
			case policyResults, ok := <-resultsChan:
				if ok {
					allRuleResults[policyResults.pkg] = policyResults.ruleResults
				} else {
					resultsChan = nil
				}
			case err, ok := <-errorChan:
				if ok {
					errors = append(errors, err)
				} else {
					errorChan = nil
				}

			}
			if resultsChan == nil && errorChan == nil {
				break
			}
		}
		if len(errors) > 0 {
			return nil, fmt.Errorf("Encountered %d errors", len(errors))
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

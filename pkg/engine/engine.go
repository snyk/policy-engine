package engine

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/storage/inmem"
	"github.com/snyk/policy-engine/pkg/data"
	"github.com/snyk/policy-engine/pkg/logging"
	"github.com/snyk/policy-engine/pkg/metrics"
	"github.com/snyk/policy-engine/pkg/models"
	"github.com/snyk/policy-engine/pkg/policy"
)

// Engine is responsible for evaluating some States with a given set of rules.
type Engine struct {
	logger             logging.Logger
	metrics            metrics.Metrics
	policies           []policy.Policy
	compiler           *ast.Compiler
	store              storage.Store
	ruleIDs            map[string]bool
	runAllRules        bool
	resourcesResolvers []policy.ResourcesResolver
}

// EngineOptions contains options for initializing an Engine instance
type EngineOptions struct {
	// Providers contains functions that produce parsed OPA modules or data documents.
	Providers []data.Provider
	// RuleIDs determines which rules are executed. When this option is empty or
	// unspecified, all rules will be run.
	RuleIDs map[string]bool
	// Logger is an optional instance of the logger.Logger interface
	Logger logging.Logger
	// Metrics is an optional instance of the metrics.Metrics interface
	Metrics metrics.Metrics
	// ResourceResolvers is a list of functions that return a resource state for
	// the given ResourceRequest. They will be invoked in order until a result is
	// returned with ScopeFound set to true.
	ResourcesResolvers []policy.ResourcesResolver
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
	logger.Info(ctx, "Initializing engine")
	consumer := NewPolicyConsumer()
	if err := policy.RegoAPIProvider(ctx, consumer); err != nil {
		logger.Error(ctx, "Failed to load rego API")
		return nil, fmt.Errorf("%w: %v", FailedToLoadRegoAPI, err)
	}
	providersStart := time.Now()
	for _, p := range options.Providers {
		if err := p(ctx, consumer); err != nil {
			logger.Error(ctx, "Failed to consume rule and data providers")
			return nil, fmt.Errorf("%w: %v", FailedToLoadRules, err)
		}
	}
	m.Timer(ctx, metrics.PROVIDERS_LOAD_TIME, "", metrics.Labels{}).
		Record(time.Now().Sub(providersStart))
	logger.WithField(logging.MODULES, len(consumer.Modules)).
		WithField(logging.DATA_DOCUMENTS, len(consumer.Documents)).
		Info(ctx, "Finished consuming providers")
	tree := ast.NewModuleTree(consumer.Modules)
	policies := []policy.Policy{}
	for _, moduleSet := range policy.ModuleSetsWithPrefix(ast.Ref{
		ast.DefaultRootDocument,
		ast.StringTerm("rules"),
	}, tree) {
		l := logger.WithField(logging.PACKAGE, moduleSet.Path.String())
		p, err := policy.PolicyFactory(moduleSet)
		if err != nil {
			l.WithField(logging.ERROR, err.Error()).
				Warn(ctx, "Error while parsing policy. It will still be loaded and accessible via data.")
		} else if p == nil {
			l.Debug(ctx, "Module did not contain a policy. It will still be loaded and accessible via data.")
		} else {
			policies = append(policies, p)
		}
	}
	compiler := ast.NewCompiler().WithCapabilities(policy.Capabilities())
	compilationStart := time.Now()
	compiler.Compile(consumer.Modules)
	m.Timer(ctx, metrics.COMPILATION_TIME, "", metrics.Labels{}).
		Record(time.Now().Sub(compilationStart))
	if len(compiler.Errors) > 0 {
		err := compiler.Errors.Error()
		logger.Error(ctx, "Failed during compilation")
		return nil, fmt.Errorf("%w: %v", FailedToCompile, err)
	}
	logger.Info(ctx, "Finished initializing engine")
	m.Counter(ctx, metrics.MODULES_LOADED, "", metrics.Labels{}).
		Add(float64(len(consumer.Modules)))
	m.Counter(ctx, metrics.DATA_DOCUMENTS_LOADED, "", metrics.Labels{}).
		Add(float64(len(consumer.Documents)))
	m.Counter(ctx, metrics.POLICIES_LOADED, "", metrics.Labels{}).
		Add(float64(len(policies)))
	return &Engine{
		logger:             logger,
		metrics:            m,
		compiler:           compiler,
		policies:           policies,
		store:              inmem.NewFromObject(consumer.Documents),
		ruleIDs:            options.RuleIDs,
		runAllRules:        len(options.RuleIDs) < 1,
		resourcesResolvers: options.ResourcesResolvers,
	}, nil
}

type policyResults struct {
	pkg         string
	err         error
	ruleResults []models.RuleResults
}

// EvalOptions contains options for Engine.Eval
type EvalOptions struct {
	// Inputs are the State instances that the engine should evaluate.
	Inputs []models.State
}

// Eval evaluates the given states using the rules that the engine was initialized with.
func (e *Engine) Eval(ctx context.Context, options *EvalOptions) *models.Results {
	e.logger.Debug(ctx, "Beginning evaluation")
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
				e.logger.WithField("package", p.Package()).
					Warn(ctx, "Failed to extract ID from policy")
				continue
			}
			if !e.ruleIDs[id] {
				continue
			}
			policies = append(policies, p)
		}
		e.metrics.Timer(ctx, metrics.RULE_SELECTION_TIME, "", metrics.Labels{}).
			Record(time.Now().Sub(ruleSelectionStart))
	}
	results := []models.Result{}
	for idx, state := range options.Inputs {
		options := policy.EvalOptions{
			RegoOptions:        regoOptions,
			Input:              &state,
			ResourcesResolvers: e.resourcesResolvers,
		}
		allRuleResults := []models.RuleResults{}
		resultsChan := make(chan policyResults)
		var wg sync.WaitGroup
		ruleEvalCounter := e.metrics.Counter(ctx, metrics.RULES_EVALUATED, "", metrics.Labels{
			metrics.INPUT_IDX: fmt.Sprint(idx),
		})
		totalEvalStart := time.Now()
		go func() {
			for _, p := range policies {
				if !p.InputTypeMatches(state.InputType) {
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
					e.metrics.Timer(ctx, metrics.RULE_EVAL_TIME, "", labels).
						Record(time.Now().Sub(evalStart))
					for _, r := range ruleResults {
						e.metrics.Counter(ctx, metrics.RESULTS_PRODUCED, "", labels).
							Add(float64(len(r.Results)))
					}
					resultsChan <- policyResults{
						pkg:         pkg,
						err:         err,
						ruleResults: ruleResults,
					}
				}(p)
				ruleEvalCounter.Inc()
			}
			wg.Wait()
			close(resultsChan)
		}()
		errCounter := e.metrics.Counter(ctx, metrics.POLICY_ERRORS, "", metrics.Labels{})
		for {
			select {
			case policyResults, ok := <-resultsChan:
				if !ok {
					resultsChan = nil
					break
				}
				if policyResults.err != nil {
					e.logger.WithField(logging.PACKAGE, policyResults.pkg).
						WithError(policyResults.err).
						Warn(ctx, "Failed to evaluate policy")
					errCounter.Inc()
					allRuleResults = append(allRuleResults, policyResults.ruleResults...)
				} else {
					e.logger.WithField(logging.PACKAGE, policyResults.pkg).
						Debug(ctx, "Completed policy evaluation")
					allRuleResults = append(allRuleResults, policyResults.ruleResults...)
				}
			}
			if resultsChan == nil {
				break
			}
		}
		e.metrics.Timer(ctx, metrics.TOTAL_RULE_EVAL_TIME, "", metrics.Labels{
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
	}
}

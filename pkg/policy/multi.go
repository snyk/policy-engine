package policy

import (
	"context"
	"fmt"

	"github.com/open-policy-agent/opa/rego"
	"github.com/snyk/policy-engine/pkg/logging"
	"github.com/snyk/policy-engine/pkg/models"
)

// ProcessSingleResultSet functions extract RuleResult models from the ResultSet of
// multi-resource type rules.
type ProcessMultiResultSet func(
	resultSet rego.ResultSet,
	metadata Metadata,
	defaultRemediation string,
	resources map[string]*ruleResultBuilder,
) ([]models.RuleResult, error)

// MultiResourcePolicy represents a policy that takes multiple resources as input.
type MultiResourcePolicy struct {
	*BasePolicy
	processResultSet ProcessMultiResultSet
}

// Eval will evaluate the policy on the given input.
func (p *MultiResourcePolicy) Eval(
	ctx context.Context,
	options EvalOptions,
) ([]models.RuleResults, error) {
	logger := options.Logger
	if logger == nil {
		logger = logging.DefaultLogger
	}
	logger = logger.WithField(logging.PACKAGE, p.Package()).
		WithField(logging.POLICY_TYPE, "multi_resource").
		WithField(logging.JUDGEMENT_NAME, p.judgementRule.name).
		WithField(logging.JUDGEMENT_KEY, p.judgementRule.key)
	output := models.RuleResults{}
	output.Package_ = p.pkg
	metadata, err := p.Metadata(ctx, options.RegoOptions)
	if err != nil {
		logger.Error(ctx, "Failed to query metadata")
		err = fmt.Errorf("%w: %v", FailedToQueryMetadata, err)
		output.Errors = append(output.Errors, err.Error())
		return []models.RuleResults{output}, err
	}
	metadata.copyToRuleResults(&output)
	opts := append(
		options.RegoOptions,
		rego.Query(p.judgementRule.query()),
		rego.ParsedInput(options.InputValue),
	)
	builtins := NewBuiltins(options.Input, options.ResourcesResolver)
	opts = append(opts, builtins.Rego()...)
	query, err := rego.New(opts...).PrepareForEval(ctx)
	if err != nil {
		logger.Error(ctx, "Failed to prepare for eval")
		err = fmt.Errorf("%w: %v", FailedToPrepareForEval, err)
		output.Errors = append(output.Errors, err.Error())
		return []models.RuleResults{output}, err
	}
	resultSet, err := query.Eval(ctx)
	if err != nil {
		logger.Error(ctx, "Failed to evaluate rule")
		err = fmt.Errorf("%w: %v", FailedToEvaluateRule, err)
		output.Errors = append(output.Errors, err.Error())
		return []models.RuleResults{output}, err
	}
	resources, err := p.resources(ctx, opts)
	if err != nil {
		logger.Error(ctx, "Failed to query resources")
		err = fmt.Errorf("%w: %v", FailedToQueryResources, err)
		output.Errors = append(output.Errors, err.Error())
		return []models.RuleResults{output}, err
	}
	defaultRemediation := metadata.RemediationFor(options.Input.InputType)
	ruleResults, err := p.processResultSet(
		resultSet,
		metadata,
		defaultRemediation,
		resources,
	)
	if err != nil {
		logger.Error(ctx, "Failed to process results")
		err = fmt.Errorf("%w: %v", FailedToProcessResults, err)
		output.Errors = append(output.Errors, err.Error())
		return []models.RuleResults{output}, err
	}
	output.ResourceTypes = builtins.ResourceTypes()
	output.Results = ruleResults
	return []models.RuleResults{output}, nil
}

// This is a ProcessMultiResultSet func for the new deny[info] style rules
func processMultiDenyPolicyResult(
	resultSet rego.ResultSet,
	metadata Metadata,
	defaultRemediation string,
	resources map[string]*ruleResultBuilder,
) ([]models.RuleResult, error) {
	policyResults := []policyResult{}
	if err := unmarshalResultSet(resultSet, &policyResults); err != nil {
		return nil, err
	}

	builders := map[string]*ruleResultBuilder{}
	for correlation, builder := range resources {
		builders[correlation] = builder
		builder.passed = true
		builder.severity = metadata.Severity
		builder.remediation = defaultRemediation
	}

	for _, result := range policyResults {
		correlation := result.GetCorrelation()
		var builder *ruleResultBuilder
		if b, ok := builders[correlation]; ok {
			builder = b
		} else {
			builder = newRuleResultBuilder()
			builders[correlation] = builder
		}

		builder.passed = false
		builder.messages = append(builder.messages, result.Message)
		if result.ResourceType != "" {
			builder.resourceType = result.ResourceType
		}

		if result.Resource != nil {
			builder.addResource(result.Resource.Key())
			for _, attr := range result.Attributes {
				builder.addResourceAttribute(result.Resource.Key(), attr)
			}
		}
		if result.Remediation != "" {
			builder.remediation = result.Remediation
		}
		if result.Severity != "" {
			builder.severity = result.Severity
		}
	}

	results := []models.RuleResult{}
	for _, builder := range builders {
		results = append(results, builder.toRuleResult())
	}
	return results, nil
}

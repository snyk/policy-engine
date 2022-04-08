package semantics

import (
	"context"
	"fmt"
	"sort"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/topdown"
	"github.com/open-policy-agent/opa/topdown/builtins"

	"github.com/snyk/unified-policy-engine/pkg/input"
	"github.com/snyk/unified-policy-engine/pkg/upe"
)

type AdvancedRule struct {
	Name string
	Ref  ast.Ref
}

func DetectAdvancedRule(
	worker Worker,
	ctx context.Context,
	rule upe.RuleInfo,
) (Semantics, error) {
	resourceType := ""
	err := worker.Eval(
		ctx,
		nil,
		struct{}{},
		rule.Module.Append(ast.StringTerm("resource_type")),
		&resourceType,
	)
	if err != nil {
		return nil, err
	}

	if resourceType != "MULTIPLE" && resourceType != "" {
		return nil, fmt.Errorf("resource_type needs to be MULTIPLE for advanced rule")
	}

	return &AdvancedRule{Name: rule.Name, Ref: rule.Module}, nil
}

func (rule *AdvancedRule) Run(
	worker Worker,
	ctx context.Context,
	input *input.Input,
) (Report, error) {
	overrides := map[string]topdown.BuiltinFunc{
		"snyk.resources": func(bctx topdown.BuiltinContext, operands []*ast.Term, iter func(*ast.Term) error) error {
			if len(operands) != 2 {
				return fmt.Errorf("Expected one argument to snyk.resources")
			}
			resourceType, err := builtins.StringOperand(operands[0].Value, 0)
			if err != nil {
				return err
			}

			resources, ok := input.Resources[string(resourceType)]
			if !ok {
				return nil
			}

			ret := map[string]interface{}{}
			for k, resource := range resources {
				ret[k] = resource.Value
			}
			val, err := ast.InterfaceToValue(ret)
			if err != nil {
				return err
			}
			iter(ast.NewTerm(val))
			return nil
		},
	}

	denies := []RegoDeny{}
	err := worker.Eval(
		ctx,
		overrides,
		struct{}{},
		rule.Ref.Append(ast.StringTerm("deny")),
		&denies,
	)
	if err != nil {
		return nil, err
	}

	resourceInfos := []RegoDeny{}
	err = worker.Eval(ctx,
		overrides,
		struct{}{},
		rule.Ref.Append(ast.StringTerm("resources")),
		&resourceInfos,
	)
	if err != nil {
		return nil, err
	}

	byCorrelation := map[string]*RuleReport{}

	for _, deny := range denies {
		correlation := deny.GetCorrelation()

		if _, ok := byCorrelation[correlation]; !ok {
			byCorrelation[correlation] = &RuleReport{
				Name:      rule.Name,
				Pass:      false,
				Resources: map[string]*RuleResourceReport{},
			}
		}

		byCorrelation[correlation].Messages = append(
			byCorrelation[correlation].Messages,
			deny.Message,
		)

		if deny.Resource != nil {
			rid := deny.Resource.Id
			byCorrelation[correlation].Resources[rid] = &RuleResourceReport{
				Id:   deny.Resource.Id,
				Type: deny.Resource.Type,
			}

			byCorrelation[correlation].Resources[rid].Attributes = append(
				byCorrelation[correlation].Resources[rid].Attributes,
				deny.Attributes...,
			)
		}
	}

	for _, resourceInfo := range resourceInfos {
		correlation := resourceInfo.GetCorrelation()

		if _, ok := byCorrelation[correlation]; !ok {
			byCorrelation[correlation] = &RuleReport{
				Name:      rule.Name,
				Pass:      true,
				Resources: map[string]*RuleResourceReport{},
			}
		}

		if resourceInfo.Resource != nil {
			rid := resourceInfo.Resource.Id
			byCorrelation[correlation].Resources[rid] = &RuleResourceReport{
				Id:   resourceInfo.Resource.Id,
				Type: resourceInfo.Resource.Type,
			}

			byCorrelation[correlation].Resources[rid].Attributes = append(
				byCorrelation[correlation].Resources[rid].Attributes,
				resourceInfo.Attributes...,
			)
		}
	}

	// Sort for consistency
	report := Report{}
	correlationKeys := []string{}
	for k := range byCorrelation {
		correlationKeys = append(correlationKeys, k)
	}
	sort.Strings(correlationKeys)
	for _, k := range correlationKeys {
		report = append(report, byCorrelation[k])
	}
	return report, nil
}

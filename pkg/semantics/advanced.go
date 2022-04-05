package semantics

import (
	"context"
	"fmt"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/topdown"
	"github.com/open-policy-agent/opa/topdown/builtins"

	"github.com/snyk/upe/pkg/input"
)

type AdvancedRule struct {
	Name string
}

func DetectAdvancedRule(
	worker Worker,
	ctx context.Context,
	ruleName string,
) (Semantics, error) {
	resourceType := ""
	err := worker.Eval(ctx, nil, struct{}{}, "data.rules."+ruleName+".resource_type", &resourceType)
	if err != nil {
		return nil, err
	}

	if resourceType != "MULTIPLE" {
		return nil, fmt.Errorf("resource_type needs to be MULTIPLE for advanced rule")
	}

	return &AdvancedRule{Name: ruleName}, nil
}

func (rule *AdvancedRule) Run(
	worker Worker,
	ctx context.Context,
	input *input.Input,
) (RuleReport, error) {
	ruleResourceReports := []RuleResourceReport{}
	policy := []interface{}{}

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

	err := worker.Eval(ctx, overrides, struct{}{}, "data.rules."+rule.Name+".policy", &policy)
	if err != nil {
		return nil, err
	}
	return ruleResourceReports, nil
}

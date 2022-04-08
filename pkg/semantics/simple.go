package semantics

import (
	"context"
	"fmt"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/topdown"

	"github.com/snyk/unified-policy-engine/pkg/input"
	"github.com/snyk/unified-policy-engine/pkg/upe"
)

type SimpleRule struct {
	Name         string
	Ref          ast.Ref
	ResourceType string
}

func DetectSimpleRule(
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

	if resourceType == "MULTIPLE" {
		return nil, fmt.Errorf("resource_type set to MULTIPLE for simple rule")
	}

	if resourceType == "" {
		return nil, fmt.Errorf("resource_type omitted for simple rule")
	}

	return &SimpleRule{
		Name:         rule.Name,
		Ref:          rule.Module,
		ResourceType: resourceType,
	}, nil
}

func (rule *SimpleRule) Builtins(*input.Input) map[string]*topdown.Builtin {
	return map[string]*topdown.Builtin{}
}

func (rule *SimpleRule) Run(
	worker Worker,
	ctx context.Context,
	input *input.Input,
) (Report, error) {
	report := Report{}

	if resources, ok := input.Resources[rule.ResourceType]; ok {
		for _, resource := range resources {
			infos := []RegoDeny{}
			err := worker.Eval(
				ctx,
				nil,
				resource.Value,
				rule.Ref.Append(ast.StringTerm("deny")),
				&infos,
			)
			if err != nil {
				return report, err
			}

			resources := map[string]*RuleResourceReport{}
			resources[resource.Id] = &RuleResourceReport{
				Id:   resource.Id,
				Type: resource.Type,
			}

			ruleReport := RuleReport{
				Name:      rule.Name,
				Pass:      true,
				Messages:  []string{},
				Resources: resources,
			}

			for _, info := range infos {
				ruleReport.Pass = false
				if len(info.Message) > 0 {
					ruleReport.Messages = append(
						ruleReport.Messages,
						info.Message,
					)
				}
				if len(info.Attributes) > 0 {
					resources[resource.Id].Attributes = append(
						resources[resource.Id].Attributes,
						info.Attributes...,
					)
				}
			}

			report = append(report, &ruleReport)
		}
	}

	return report, nil
}

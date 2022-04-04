package semantics

import (
	"context"
	"fmt"

	"github.com/open-policy-agent/opa/topdown"
	"github.com/snyk/upe/pkg/input"
)

// TODO: Consider sharing this structure.
type Info struct {
	Message string `json:"message,omitempty"`
}

type SimpleRule struct {
	Name         string
	ResourceType string
}

func DetectSimpleRule(
	worker Worker,
	ctx context.Context,
	ruleName string,
) (Semantics, error) {
	resourceType := ""
	err := worker.Eval(ctx, nil, struct{}{}, "data.rules."+ruleName+".resource_type", &resourceType)
	if err != nil {
		return nil, err
	}

	if resourceType == "MULTIPLE" {
		return nil, fmt.Errorf("resource_type set to MULTIPLE for simple rule")
	}

	return &SimpleRule{Name: ruleName, ResourceType: resourceType}, nil
}

func (rule *SimpleRule) Builtins(*input.Input) map[string]*topdown.Builtin {
	return map[string]*topdown.Builtin{}
}

func (rule *SimpleRule) Run(
	worker Worker,
	ctx context.Context,
	input *input.Input,
) (RuleReport, error) {
	ruleResourceReports := []RuleResourceReport{}

	if resources, ok := input.Resources[rule.ResourceType]; ok {
		for _, resource := range resources {
			infos := []Info{}
			err := worker.Eval(ctx, nil, resource.Value, "data.rules."+rule.Name+".deny", &infos)
			if err != nil {
				return nil, err
			}

			ruleResourceReport := RuleResourceReport{
				ResourceId:   resource.Id,
				RuleName:     rule.Name,
				RulePass:     true,
				RuleMessages: []string{},
			}

			for _, info := range infos {
				ruleResourceReport.RulePass = false
				if len(info.Message) > 0 {
					ruleResourceReport.RuleMessages = append(
						ruleResourceReport.RuleMessages,
						info.Message,
					)
				}
			}

			ruleResourceReports = append(ruleResourceReports, ruleResourceReport)
		}
	}

	return ruleResourceReports, nil
}

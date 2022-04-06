package semantics

import (
	"context"
	"fmt"

	"github.com/open-policy-agent/opa/topdown"
	"github.com/snyk/unified-policy-engine/pkg/input"
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
) (Report, error) {
	report := Report{}

	if resources, ok := input.Resources[rule.ResourceType]; ok {
		for _, resource := range resources {
			infos := []Info{}
			err := worker.Eval(ctx, nil, resource.Value, "data.rules."+rule.Name+".deny", &infos)
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
			}

			report = append(report, &ruleReport)
		}
	}

	return report, nil
}

package semantics

import (
	"context"
	"fmt"
	"strings"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/topdown"
	"github.com/open-policy-agent/opa/types"
	"github.com/snyk/upe/pkg/input"
)

type Worker interface {
	Eval(
		ctx context.Context,
		overrides map[string]topdown.BuiltinFunc,
		input interface{},
		ref string,
		output interface{},
	) error
}

type RuleReport = []RuleResourceReport

type RuleResourceReport struct {
	ResourceId   string   `json:"resource_id"`
	RuleName     string   `json:"rule_name"`
	RulePass     bool     `json:"rule_pass"`
	RuleMessages []string `json:"rule_messages"`
}

type Semantics interface {
	Run(Worker, context.Context, *input.Input) (RuleReport, error)
}

type SemanticsDetector = func(Worker, context.Context, string) (Semantics, error)

func ConcatSemanticsDetector(detectors []SemanticsDetector) SemanticsDetector {
	return func(worker Worker, ctx context.Context, ruleName string) (Semantics, error) {
		errors := []string{}
		for _, detector := range detectors {
			semantics, err := detector(worker, ctx, ruleName)
			if err == nil {
				return semantics, nil
			} else {
				errors = append(errors, fmt.Sprintf("%s", err))
			}
		}
		return nil, fmt.Errorf("No detectors matched, errors: %s", strings.Join(errors, ", "))
	}
}

var DetectSemantics SemanticsDetector = ConcatSemanticsDetector([]SemanticsDetector{
	DetectSimpleRule,
	DetectAdvancedRule,
})

// Compilation needs to be aware of all builtins that rules can use.
func Builtins() map[string]*topdown.Builtin {
	return map[string]*topdown.Builtin{
		"snyk.resources": {
			Decl: &ast.Builtin{
				Name: "snyk.resources",
				Decl: types.NewFunction(
					types.Args(types.A),
					types.A,
				),
			},
			Func: doNothing,
		},
	}
}

func doNothing(topdown.BuiltinContext, []*ast.Term, func(*ast.Term) error) error {
	return nil
}

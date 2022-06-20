package policy

import (
	"context"
	"fmt"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/topdown/builtins"
	"github.com/snyk/policy-engine/pkg/models"
)

type Query struct {
	ResourcesResolver ResourcesResolver
}

func (*Query) decl() *rego.Function {
	return &rego.Function{
		Name:    queryName,
		Decl:    builtinDeclarations[queryName],
		Memoize: true,
	}
}

func (q *Query) impl(bctx rego.BuiltinContext, operands []*ast.Term) (*ast.Term, error) {
	scopeOpaObj, err := builtins.ObjectOperand(operands[0].Value, 0)
	if err != nil {
		return nil, err
	}
	query := ResourcesQuery{Scope: map[string]string{}}
	if err := scopeOpaObj.Iter(func(k, v *ast.Term) error {
		key := string(k.Value.(ast.String))
		if key == "resource_type" {
			query.ResourceType = string(v.Value.(ast.String))
		} else if key == "scope" {
			err := v.Value.(ast.Object).Iter(func(k, v *ast.Term) error {
				scopeKey := string(k.Value.(ast.String))
				scopeValue := string(v.Value.(ast.String))
				query.Scope[scopeKey] = scopeValue
				return nil
			})
			if err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}

	resources, err := q.ResolveResources(bctx.Context, query)
	if err != nil {
		return nil, err
	}

	regoResources := resourceStatesToRegoInputs(resources)

	val, err := ast.InterfaceToValue(regoResources)
	if err != nil {
		return nil, err
	}
	return ast.NewTerm(val), nil
}

func (q *Query) ResolveResources(ctx context.Context, query ResourcesQuery) ([]models.ResourceState, error) {
	resolver := q.ResourcesResolver
	res, err := resolver.Resolve(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("error in ResourcesResolver: %s", err)
	}
	if res.ScopeFound {
		return res.Resources, nil
	}
	return []models.ResourceState{}, nil
}

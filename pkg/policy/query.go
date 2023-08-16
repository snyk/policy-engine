// © 2022-2023 Snyk Limited All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package policy

import (
	"context"
	"fmt"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/topdown"
	"github.com/open-policy-agent/opa/types"

	"github.com/snyk/policy-engine/pkg/models"
	"github.com/snyk/policy-engine/pkg/rego"
)

type Query struct {
	ResourcesResolver ResourcesResolver
}

func (*Query) name() string {
	return queryName
}

func (*Query) decl() *types.Function {
	return builtinDeclarations[queryName]
}

func (q *Query) impl(bctx topdown.BuiltinContext, operands []*ast.Term) (*ast.Term, error) {
	query := ResourcesQuery{}
	if err := rego.Bind(operands[0].Value, &query); err != nil {
		return nil, err
	}

	resources, err := q.ResolveResources(bctx.Context, query)
	if err != nil {
		return nil, err
	}

	regoResources, err := resourceStatesToRegoInputs(resources)
	if err != nil {
		return nil, err
	}

	return ast.ArrayTerm(regoResources...), nil
}

func (q *Query) ResolveResources(ctx context.Context, query ResourcesQuery) ([]models.ResourceState, error) {
	res, err := q.ResourcesResolver(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("error in ResourcesResolver: %s", err)
	}
	if res.ScopeFound {
		return res.Resources, nil
	}
	return []models.ResourceState{}, nil
}

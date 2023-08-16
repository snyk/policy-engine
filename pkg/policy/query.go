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

type ResourcesQueryCache struct {
	ResourcesResolver    ResourcesResolver
	queriedResourceTypes map[string]struct{}
}

func NewResourcesQueryCache(resolver ResourcesResolver) *ResourcesQueryCache {
	return &ResourcesQueryCache{
		ResourcesResolver: resolver,
	}
}

// trackResourceTypes creates a copy of the query that tracks resource types
// used in queries in the given map.  This allows us to still use the same
// cache (across policies) but have a separate set of used resource types
// per policy.
func (q *ResourcesQueryCache) trackResourceTypes(queriedResourceTypes map[string]struct{}) *ResourcesQueryCache {
	return &ResourcesQueryCache{
		ResourcesResolver:    q.ResourcesResolver,
		queriedResourceTypes: queriedResourceTypes,
	}
}

func (*ResourcesQueryCache) name() string {
	return queryName
}

func (*ResourcesQueryCache) decl() *types.Function {
	return builtinDeclarations[queryName]
}

func (q *ResourcesQueryCache) impl(bctx topdown.BuiltinContext, operands []*ast.Term) (*ast.Term, error) {
	query := ResourcesQuery{}
	if err := rego.Bind(operands[0].Value, &query); err != nil {
		return nil, err
	}

	// Track queried resource types
	if q.queriedResourceTypes != nil {
		q.queriedResourceTypes[query.ResourceType] = struct{}{}
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

func (q *ResourcesQueryCache) ResolveResources(ctx context.Context, query ResourcesQuery) ([]models.ResourceState, error) {
	res, err := q.ResourcesResolver(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("error in ResourcesResolver: %s", err)
	}
	if res.ScopeFound {
		return res.Resources, nil
	}
	return []models.ResourceState{}, nil
}

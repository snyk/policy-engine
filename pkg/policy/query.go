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
	"encoding/json"
	"fmt"
	"sync"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/topdown"
	"github.com/open-policy-agent/opa/v1/types"

	"github.com/snyk/policy-engine/pkg/models"
	"github.com/snyk/policy-engine/pkg/rego"
)

type ResourcesQueryCache struct {
	ResourcesResolver    ResourcesResolver
	queriedResourceTypes map[string]struct{}

	// This cache is primarily meant to save memory rather than time by
	// ensuring we reuse the same pointers to the terms.
	cacheTerms map[string]*ast.Term
	cacheMutex *sync.RWMutex
}

func NewResourcesQueryCache(resolver ResourcesResolver) *ResourcesQueryCache {
	return &ResourcesQueryCache{
		ResourcesResolver: resolver,
		cacheTerms:        map[string]*ast.Term{},
		cacheMutex:        &sync.RWMutex{},
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
		cacheTerms:           q.cacheTerms,
		cacheMutex:           q.cacheMutex,
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

	// Construct cache key
	cacheKeyBytes, err := json.Marshal(query)
	if err != nil {
		return nil, err
	}
	cacheKey := string(cacheKeyBytes)

	// Try cache first
	q.cacheMutex.RLock()
	cached, ok := q.cacheTerms[cacheKey]
	q.cacheMutex.RUnlock()
	if ok {
		return cached, nil
	}

	// Use resolver
	q.cacheMutex.Lock()
	defer q.cacheMutex.Unlock()
	resources, err := q.ResolveResources(bctx.Context, query)
	if err != nil {
		return nil, err
	}
	regoResources, err := resourceStatesToRegoInputs(resources)
	if err != nil {
		return nil, err
	}
	result := ast.ArrayTerm(regoResources...)
	q.cacheTerms[cacheKey] = result
	return result, nil
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

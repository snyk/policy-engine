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

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/topdown"
	"github.com/open-policy-agent/opa/topdown/builtins"
	"github.com/open-policy-agent/opa/types"
	"github.com/snyk/policy-engine/pkg/models"
)

type QueryCache struct {
	lock  *sync.RWMutex
	cache map[string]*ast.Term
}

func NewQueryCache() *QueryCache {
	return &QueryCache{
		lock:  &sync.RWMutex{},
		cache: map[string]*ast.Term{},
	}
}

func (c *QueryCache) key(q ResourcesQuery) string {
	bytes, _ := json.Marshal(q) // ResourcesQuery is safe to serialize
	return string(bytes)
}

func (c *QueryCache) Get(q ResourcesQuery) *ast.Term {
	c.lock.RLock()
	defer c.lock.RUnlock()
	if t, ok := c.cache[c.key(q)]; ok {
		return t
	}
	return nil
}

func (c *QueryCache) Put(q ResourcesQuery, t *ast.Term) {
	c.lock.Lock()
	c.cache[c.key(q)] = t
	defer c.lock.Unlock()
}

type Query struct {
	QueryCache        *QueryCache
	ResourcesResolver ResourcesResolver
}

func (*Query) name() string {
	return queryName
}

func (*Query) decl() *types.Function {
	return builtinDeclarations[queryName]
}

func (q *Query) impl(bctx topdown.BuiltinContext, operands []*ast.Term) (*ast.Term, error) {
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

	if q.QueryCache != nil {
		if t := q.QueryCache.Get(query); t != nil {
			return t, nil
		}
	}

	resources, err := q.ResolveResources(bctx.Context, query)
	if err != nil {
		return nil, err
	}

	regoResources, err := resourceStatesToRegoInputs(resources)
	if err != nil {
		return nil, err
	}

	term := ast.ArrayTerm(regoResources...)
	if q.QueryCache != nil {
		q.QueryCache.Put(query, term)
	}

	return term, nil
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

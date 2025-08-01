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
	"embed"
	"fmt"
	"sort"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/topdown"
	"github.com/open-policy-agent/opa/v1/types"
	"github.com/snyk/policy-engine/pkg/data"
	"github.com/snyk/policy-engine/pkg/models"
	"github.com/snyk/policy-engine/pkg/policy/inferattributes"
	"github.com/snyk/policy-engine/pkg/snapshot_testing"
)

//go:embed regoapi
var regoApi embed.FS

// RegoAPIProvider is a provider for the embedded 'snyk' and 'fugue' Rego APIs.
var RegoAPIProvider = data.FSProvider(regoApi, "regoapi")

// ResourcesQuery describes a request for a specific resource type from the given scope.
// An empty scope is interpreted as the scope of the current input.
type ResourcesQuery struct {
	ResourceType string            `json:"resource_type" rego:"resource_type"`
	Scope        map[string]string `json:"scope" rego:"scope"`
}

// ResourcesResult contains an indication of whether the Scope specified in the
// ResourcesQuery was found and a slice of resources.
type ResourcesResult struct {
	ScopeFound bool
	Resources  []models.ResourceState
}

type ResourcesResolver func(ctx context.Context, req ResourcesQuery) (ResourcesResult, error)

func (l ResourcesResolver) And(r ResourcesResolver) ResourcesResolver {
	return func(ctx context.Context, req ResourcesQuery) (ResourcesResult, error) {
		result := ResourcesResult{
			ScopeFound: false,
			Resources:  []models.ResourceState{},
		}
		lresult, err := l(ctx, req)
		if err != nil {
			return result, err
		}
		result.ScopeFound = result.ScopeFound || lresult.ScopeFound
		result.Resources = append(result.Resources, lresult.Resources...)
		rresult, err := r(ctx, req)
		if err != nil {
			return result, err
		}
		result.ScopeFound = result.ScopeFound || rresult.ScopeFound
		result.Resources = append(result.Resources, rresult.Resources...)
		return result, nil
	}
}

func (l ResourcesResolver) Or(r ResourcesResolver) ResourcesResolver {
	return func(ctx context.Context, req ResourcesQuery) (ResourcesResult, error) {
		result := ResourcesResult{
			ScopeFound: false,
			Resources:  []models.ResourceState{},
		}
		lresult, err := l(ctx, req)
		if err != nil {
			return result, err
		}
		result.ScopeFound = result.ScopeFound || lresult.ScopeFound
		result.Resources = append(result.Resources, lresult.Resources...)
		if result.ScopeFound || r == nil {
			return result, nil
		}
		rresult, err := r(ctx, req)
		if err != nil {
			return result, err
		}
		result.ScopeFound = result.ScopeFound || rresult.ScopeFound
		result.Resources = append(result.Resources, rresult.Resources...)
		return result, nil
	}
}

// Constants for builtin functions
const currentInputTypeName = "__current_input_type"
const inputResourceTypesName = "__input_resource_types"
const queryName = "__query"
const snykRelationsCacheForward = "__snyk_relations_cache_forward"
const snykRelationsCacheBackward = "__snyk_relations_cache_backward"

var builtinDeclarations = map[string]*types.Function{
	currentInputTypeName: types.NewFunction(
		types.Args(),
		types.S,
	),
	inputResourceTypesName: types.NewFunction(
		types.Args(),
		types.NewSet(types.S),
	),
	queryName: types.NewFunction(
		types.Args(
			types.NewObject(
				[]*types.StaticProperty{
					types.NewStaticProperty("resource_type", types.S),
					types.NewStaticProperty("scope", types.NewObject(
						nil,
						types.NewDynamicProperty(types.S, types.S),
					)),
				},
				nil,
			),
		),
		types.NewArray(nil, types.NewObject(
			nil,
			types.NewDynamicProperty(types.S, types.A),
		)),
	),
	snykRelationsCacheForward: types.NewFunction(
		types.Args(),
		types.NewObject(
			nil,
			types.NewDynamicProperty(types.A, types.A),
		),
	),
	snykRelationsCacheBackward: types.NewFunction(
		types.Args(),
		types.NewObject(
			nil,
			types.NewDynamicProperty(types.A, types.A),
		),
	),
	snapshot_testing.MatchBuiltin.Name: snapshot_testing.MatchBuiltin.Decl,
}

// Capabilities returns a Capabilities that includes the the policy engine builtins.
func Capabilities() *ast.Capabilities {
	builtins := []*ast.Builtin{}
	for name, decl := range builtinDeclarations {
		builtins = append(builtins, &ast.Builtin{
			Name: name,
			Decl: decl,
		})
	}
	base := ast.CapabilitiesForThisVersion()
	for _, builtin := range base.Builtins {
		if _, ok := allowedBuiltins[builtin.Name]; ok {
			builtins = append(builtins, builtin)
		}
	}
	return &ast.Capabilities{
		Builtins:       builtins,
		AllowNet:       []string{},
		FutureKeywords: base.FutureKeywords,
	}
}

type builtin interface {
	name() string
	decl() *types.Function
	impl(bctx topdown.BuiltinContext, operands []*ast.Term) (*ast.Term, error)
}

func resourceStateToRegoInput(resource models.ResourceState) (*ast.Term, error) {
	obj := map[string]interface{}{}
	obj["id"] = resource.Id
	obj["_id"] = resource.Id
	obj["_type"] = resource.ResourceType
	obj["_namespace"] = resource.Namespace
	if resource.Meta == nil {
		obj["_meta"] = map[string]interface{}{}
	} else {
		obj["_meta"] = resource.Meta
	}
	tags := map[string]interface{}{}
	for k, v := range resource.Tags {
		tags[k] = v
	}
	obj["_tags"] = tags
	for k, attr := range resource.Attributes {
		// If we have a non-null, non-blank ID from the resource, we should
		// retain that value. Otherwise, we should keep the logical ID that
		// we've already set.
		if k == "id" {
			if id, ok := attr.(string); ok && id != "" {
				obj[k] = attr
			}
		} else {
			obj[k] = attr
		}
	}
	val, err := ast.InterfaceToValue(obj)
	if err != nil {
		return nil, err
	}
	term := ast.NewTerm(val)
	inferattributes.DecorateResource(resource, term)
	return term, nil
}

func resourceStatesToRegoInputs(resources []models.ResourceState) ([]*ast.Term, error) {
	ret := make([]*ast.Term, len(resources))
	for i, resource := range resources {
		term, err := resourceStateToRegoInput(resource)
		if err != nil {
			return nil, err
		}
		ret[i] = term
	}
	return ret, nil
}

type currentInputType struct {
	input *models.State
}

func (c *currentInputType) name() string {
	return currentInputTypeName
}

func (c *currentInputType) decl() *types.Function {
	return builtinDeclarations[currentInputTypeName]
}

func (c *currentInputType) impl(
	bctx topdown.BuiltinContext,
	operands []*ast.Term,
) (*ast.Term, error) {
	return ast.StringTerm(c.input.InputType), nil
}

type inputResourceTypes struct {
	input *models.State
}

func (c *inputResourceTypes) name() string {
	return inputResourceTypesName
}

func (c *inputResourceTypes) decl() *types.Function {
	return builtinDeclarations[inputResourceTypesName]
}

func (c *inputResourceTypes) impl(
	bctx topdown.BuiltinContext,
	operands []*ast.Term,
) (*ast.Term, error) {
	rts := make([]*ast.Term, 0, len(c.input.Resources))
	for rt := range c.input.Resources {
		rts = append(rts, ast.StringTerm(rt))
	}
	return ast.SetTerm(rts...), nil
}

type relationsCache struct {
	forward bool
	cache   *RelationsCache
}

func (rc relationsCache) name() string {
	if rc.forward {
		return snykRelationsCacheForward
	} else {
		return snykRelationsCacheBackward
	}
}

func (rc relationsCache) decl() *types.Function {
	return builtinDeclarations[rc.name()]
}

func (rc relationsCache) impl(
	bctx topdown.BuiltinContext,
	operands []*ast.Term,
) (*ast.Term, error) {
	if rc.cache == nil {
		return ast.ObjectTerm(), nil
	} else {
		if rc.forward {
			return ast.NewTerm(rc.cache.Forward), nil
		} else {
			return ast.NewTerm(rc.cache.Backward), nil
		}
	}
}

type snapshotTestingMatch struct{}

func (b snapshotTestingMatch) name() string {
	return snapshot_testing.MatchBuiltin.Name
}

func (b snapshotTestingMatch) decl() *types.Function {
	return snapshot_testing.MatchBuiltin.Decl
}

func (b snapshotTestingMatch) impl(
	bctx topdown.BuiltinContext,
	operands []*ast.Term,
) (*ast.Term, error) {
	return snapshot_testing.MatchNoopImpl()(bctx, operands)
}

type Builtins struct {
	resourceTypesQueried map[string]struct{} // We want a separate ref to this to make it cleaner to get resource types back out
	funcs                []builtin
}

type RelationsCache struct {
	Forward  ast.Value
	Backward ast.Value
}

func NewBuiltins(
	input *models.State,
	resourcesQuery *ResourcesQueryCache,
	relations *RelationsCache,
) *Builtins {
	resourceTypesQueried := map[string]struct{}{}

	return &Builtins{
		resourceTypesQueried: resourceTypesQueried,
		funcs: []builtin{
			resourcesQuery.trackResourceTypes(resourceTypesQueried),
			&currentInputType{input},
			&inputResourceTypes{input},
			relationsCache{forward: true, cache: relations},
			relationsCache{forward: false, cache: relations},
			snapshotTestingMatch{},
		},
	}
}

func (b *Builtins) Rego() []func(*rego.Rego) {
	r := make([]func(*rego.Rego), len(b.funcs))
	for idx, f := range b.funcs {
		r[idx] = rego.FunctionDyn(&rego.Function{
			Name: f.name(),
			Decl: f.decl(),
		}, f.impl)
	}
	return r
}

func (b *Builtins) Implementations() map[string]*topdown.Builtin {
	m := map[string]*topdown.Builtin{}
	for _, f := range b.funcs {
		name := f.name()
		impl := f.impl
		m[f.name()] = &topdown.Builtin{
			Decl: &ast.Builtin{
				Name: name,
				Decl: f.decl(),
			},
			Func: func(bctx topdown.BuiltinContext, operands []*ast.Term, iter func(*ast.Term) error) error {
				result, err := impl(bctx, operands)
				if err != nil {
					return &topdown.Error{
						Code:     topdown.BuiltinErr,
						Message:  fmt.Sprintf("%v: %v", name, err.Error()),
						Location: bctx.Location,
					}
				}
				if result == nil {
					return nil
				}
				return iter(result)
			},
		}
	}
	return m
}

func (b *Builtins) ResourceTypes() []string {
	rts := make([]string, 0, len(b.resourceTypesQueried))
	for rt := range b.resourceTypesQueried {
		rts = append(rts, rt)
	}
	sort.Strings(rts)
	return rts
}

// Copyright 2022 Snyk Ltd
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

// Look in `/pkg/hcl_interpreter/README.md` for an explanation of how this
// works.
package hcl_interpreter

import (
	"fmt"
	"github.com/hashicorp/hcl/v2"
	"github.com/spf13/afero"
	"github.com/zclconf/go-cty/cty"

	"github.com/snyk/policy-engine/pkg/hcl_interpreter/funcs"
	"github.com/snyk/policy-engine/pkg/input/schemas"
	tfschemas "github.com/snyk/policy-engine/pkg/input/schemas/tf"
	"github.com/snyk/policy-engine/pkg/internal/terraform/lang"
	"github.com/snyk/policy-engine/pkg/models"
	"github.com/snyk/policy-engine/pkg/topsort"
)

type Analysis struct {
	Fs afero.Fs

	// Module metadata
	Modules map[string]*ModuleMeta

	// Resource metadata
	Resources map[string]*ResourceMeta

	// Terms in the evaluation tree.
	Terms *TermTree

	// Any bad keys that we attempted to reference or failed to parse
	badKeys map[string]struct{}
}

func AnalyzeModuleTree(mtree *ModuleTree) *Analysis {
	analysis := &Analysis{
		Fs:                  mtree.fs,
		Modules:             map[string]*ModuleMeta{},
		Resources:           map[string]*ResourceMeta{},
		Terms:               NewTermTree(),
		badKeys:             map[string]struct{}{},
	}
	mtree.Walk(analysis)
	return analysis
}

func (v *Analysis) VisitModule(name ModuleName, meta *ModuleMeta) {
	v.Modules[ModuleNameToString(name)] = meta
}

func (v *Analysis) VisitResource(name FullName, resource *ResourceMeta) {
	resourceKey := name.ToString()
	v.Resources[resourceKey] = resource
}

func (v *Analysis) VisitTerm(name FullName, term Term) {
	v.Terms.AddTerm(name, term)
}

type dependency struct {
	destination FullName
	source      *FullName
	value       *cty.Value
}

func (v *Analysis) termDependencies(name FullName, term Term) []dependency {
	deps := []dependency{}
	term.VisitExpressions(func(expr hcl.Expression) {
		for _, traversal := range expr.Variables() {
			local, err := TraversalToLocalName(traversal)
			if err != nil {
				v.badKeys[TraversalToString(traversal)] = struct{}{}
				continue
			}

			full := FullName{Module: name.Module, Local: local}

			if prefix, _ := v.Terms.LookupByPrefix(full); prefix != nil {
				deps = append(deps, dependency{*prefix, prefix, nil})
				continue
			}

			if moduleOutput := full.AsModuleOutput(); moduleOutput != nil {
				deps = append(deps, dependency{full, moduleOutput, nil})
				continue
			}

			if asVariable, asVar, _ := full.AsVariable(); asVar != nil {
				// Rewrite variables either as default, or as module input.
				asModuleInput := full.AsModuleInput()
				isModuleInput := false
				if asModuleInput != nil {
					if mtp, _ := v.Terms.LookupByPrefix(*asModuleInput); mtp != nil {
						deps = append(deps, dependency{*asVar, mtp, nil})
						isModuleInput = true
					}
				}
				if !isModuleInput {
					deps = append(deps, dependency{*asVar, asVariable, nil})
				}
				continue
			}

			if asResourceName, _ := full.AsUncountedResourceName(); asResourceName != nil {
				// TODO: Superseded by LookupByPrefix?
				if _, ok := v.Resources[asResourceName.ToString()]; ok {
					deps = append(deps, dependency{*asResourceName, asResourceName, nil})
					continue
				}
			}

			// In other cases, just use the local name.  This is sort of
			// a catch-all and we should try to not rely on this too much.
			val := cty.StringVal(LocalNameToString(local))
			deps = append(deps, dependency{full, nil, &val})
		}
	})
	return deps
}

// Iterate all expressions to be evaluated in the "correct" order.
func (v *Analysis) orderTerms() ([]FullName, error) {
	graph := map[string][]string{}
	v.Terms.VisitTerms(func(name FullName, term Term) {
		key := name.ToString()
		graph[key] = []string{}
		deps := v.termDependencies(name, term)
		for _, dep := range deps {
			if dep.source != nil {
				graph[key] = append(graph[key], dep.source.ToString())
			}
		}
	})

	sorted, err := topsort.Topsort(graph)
	if err != nil {
		return nil, err
	}

	sortedNames := []FullName{}
	for _, key := range sorted {
		name, err := StringToFullName(key)
		if err != nil {
			v.badKeys[key] = struct{}{}
			continue
		}
		sortedNames = append(sortedNames, *name)
	}
	return sortedNames, nil
}

type Evaluation struct {
	Analysis *Analysis
	Modules  map[string]ValTree

	resourceAttributes map[string]cty.Value

	phantomAttrs *phantomAttrs

	errors []error // Errors encountered during evaluation
}

func EvaluateAnalysis(analysis *Analysis) (*Evaluation, error) {
	eval := &Evaluation{
		Analysis:           analysis,
		Modules:            map[string]ValTree{},
		resourceAttributes: map[string]cty.Value{},
		phantomAttrs:       newPhantomAttrs(),
	}

	for moduleKey := range analysis.Modules {
		eval.Modules[moduleKey] = EmptyObjectValTree()
	}

	if err := eval.evaluateTerms(); err != nil {
		return nil, err
	}

	return eval, nil
}

func (v *Evaluation) prepareTermVariables(name FullName, term Term) ValTree {
	sparse := EmptyObjectValTree()
	for _, dep := range v.Analysis.termDependencies(name, term) {
		var dependency ValTree
		if dep.source != nil {
			sourceModule := ModuleNameToString(dep.source.Module)
			dependency = BuildValTree(
				dep.destination.Local,
				LookupValTree(v.Modules[sourceModule], dep.source.Local),
			)
		} else if dep.value != nil {
			dependency = SingletonValTree(dep.destination.Local, *dep.value)
		}
		if dependency != nil {
			sparse = MergeValTree(sparse, dependency)
		}
	}
	return sparse
}

func (v *Evaluation) evaluateTerms() error {
	// Obtain order again
	order, err := v.Analysis.orderTerms()
	if err != nil {
		return err
	}

	termsByKey := map[string]Term{}
	v.Analysis.Terms.VisitTerms(func(name FullName, term Term) {
		termsByKey[name.ToString()] = term
		v.phantomAttrs.analyze(name, term)
	})

	// Evaluate terms
	for _, name := range order {
		term := termsByKey[name.ToString()]
		moduleKey := ModuleNameToString(name.Module)
		moduleMeta := v.Analysis.Modules[moduleKey]

		vars := v.prepareTermVariables(name, term)
		vars = MergeValTree(vars, SingletonValTree(LocalName{"path", "module"}, cty.StringVal(moduleMeta.Dir)))
		vars = MergeValTree(vars, SingletonValTree(LocalName{"terraform", "workspace"}, cty.StringVal("default")))

		// Add count.index if inside a counted resource.
		resourceName, _, _ := name.AsResourceName()
		if resourceName != nil {
			resourceKey := resourceName.ToString()
			if resource, ok := v.Analysis.Resources[resourceKey]; ok {
				if resource.Count {
					vars = MergeValTree(vars, SingletonValTree(LocalName{"count", "index"}, cty.NumberIntVal(0)))
				}
			}
		}

		val, diags := term.Evaluate(func(expr hcl.Expression, extraVars interface{}) (cty.Value, hcl.Diagnostics) {
			data := Data{}
			scope := lang.Scope{
				Data:     &data,
				SelfAddr: nil,
				PureOnly: false,
			}
			vars = MergeValTree(vars, extraVars) // TODO: Mutable, bad bad!
			ctx := hcl.EvalContext{
				Functions: funcs.Override(v.Analysis.Fs, scope),
				Variables: ValTreeToVariables(vars),
			}
			val, diags := expr.Value(&ctx)
			if diags.HasErrors() {
				val = cty.NullVal(val.Type())
			}
			return val, diags
		})

		if diags.HasErrors() {
			v.errors = append(v.errors, fmt.Errorf("evaluate: error: %s", diags))
		}

		v.resourceAttributes[resourceName.ToString()] = val
		val = v.phantomAttrs.add(name, val)
		singleton := SingletonValTree(name.Local, val)
		v.Modules[moduleKey] = MergeValTree(v.Modules[moduleKey], singleton)
	}

	return nil
}

func (v *Evaluation) prepareResource(resourceMeta *ResourceMeta, name FullName, val cty.Value) []models.ResourceState {
	resources := []models.ResourceState{}

	resourceKey := name.ToString()
	module := ModuleNameToString(name.Module)

	resourceType := resourceMeta.Type
	if resourceMeta.Data {
		resourceType = "data." + resourceType
	}

	if val.Type().IsTupleType() {
		for idx, child := range val.AsValueSlice() {
			resource := v.prepareResource(resourceMeta, name.AddIndex(idx), child)
			resources = append(resources, resource...)
		}
	} else {
		attrs := map[string]interface{}{}
		iface, errs := ValueToInterface(ValTreeToValue(val))
		v.errors = append(v.errors, errs...)
		if obj, ok := iface.(map[string]interface{}); ok {
			attrs = obj
		}

		metaTree := EmptyObjectValTree()
		providerConfName := ProviderConfigName(name.Module, resourceMeta.ProviderName)
		if providerConf := LookupValTree(v.Modules[module], providerConfName.Local); providerConf != nil {
			metaTree = MergeValTree(
				metaTree,
				SingletonValTree(
					[]interface{}{"terraform", "provider_config"},
					ValTreeToValue(providerConf),
				),
			)
		}

		if resourceMeta.ProviderVersionConstraint != "" {
			metaTree = MergeValTree(
				metaTree,
				SingletonValTree(
					[]interface{}{"terraform", "provider_version_constraint"},
					cty.StringVal(resourceMeta.ProviderVersionConstraint),
				),
			)
		}

		meta := map[string]interface{}{}
		if metaVal, errs := ValueToInterface(ValTreeToValue(metaTree)); len(errs) == 0 {
			if metaObj, ok := metaVal.(map[string]interface{}); ok {
				meta = metaObj
			}
		}

		// Add meta.region if present
		if tfmeta, ok := meta["terraform"].(map[string]interface{}); ok {
			if pc, ok := tfmeta["provider_config"].(map[string]interface{}); ok {
				if region, ok := pc["region"].(string); ok {
					meta["region"] = region
				}
			}
		}

		attrs = schemas.ApplyObject(attrs, tfschemas.GetSchema(resourceType))

		// TODO: Support tags again: PopulateTags(input[resourceKey])
		resources = append(resources, models.ResourceState{
			Id:           resourceKey,
			ResourceType: resourceType,
			Attributes:   attrs,
			Meta:         meta,
		})
	}

	return resources
}

func (v *Evaluation) Resources() []models.ResourceState {
	resources := []models.ResourceState{}

	for resourceKey, resourceMeta := range v.Analysis.Resources {
		resourceName, err := StringToFullName(resourceKey)
		if err != nil || resourceName == nil {
			v.Analysis.badKeys[resourceKey] = struct{}{}
			continue
		}

		resource := v.prepareResource(resourceMeta, *resourceName, v.resourceAttributes[resourceKey])
		resources = append(resources, resource...)
	}

	return resources
}

// Errors returns the non-fatal errors encountered during evaluation
func (e *Evaluation) Errors() []error {
	errors := []error{}
	for _, badKey := range e.Analysis.badKeys {
		errors = append(errors, fmt.Errorf("Bad dependency key: %s", badKey))
	}
	errors = append(errors, e.errors...)
	return errors
}

type phantomAttrs struct {
	// A set of phantom attributes per FullName.
	attrs map[string]map[string]struct{}
}

func newPhantomAttrs() *phantomAttrs {
	return &phantomAttrs{
		attrs: map[string]map[string]struct{}{},
	}
}

func (pa *phantomAttrs) analyze(name FullName, term Term) {
	term.VisitExpressions(func(expr hcl.Expression) {
		exprAttrs := ExprAttributes(expr)
		for _, traversal := range expr.Variables() {
			local, err := TraversalToLocalName(traversal)
			if err != nil {
				continue
			}

			full := FullName{Module: name.Module, Local: local}
			if asResourceName, trailing := full.AsUncountedResourceName(); asResourceName != nil {
				attrs := map[string]struct{}{}
				attrs[LocalNameToString(trailing)] = struct{}{}
				for _, attr := range exprAttrs {
					attrs[LocalNameToString(attr)] = struct{}{}
				}

				if len(attrs) > 0 {
					resourceKey := asResourceName.ToString()
					if _, ok := pa.attrs[resourceKey]; !ok {
						pa.attrs[resourceKey] = map[string]struct{}{}
					}
					for k := range attrs {
						pa.attrs[resourceKey][k] = struct{}{}
					}
				}
			}
		}
	})
}

func (pa *phantomAttrs) add(name FullName, val cty.Value) cty.Value {
	rk := name.ToString()

	var patch func(LocalName, FullName, cty.Value) cty.Value
	patch = func(local LocalName, ref FullName, val cty.Value) cty.Value {
		if val.Type().IsObjectType() {
			obj := map[string]cty.Value{}

			for k, v := range val.AsValueMap() {
				obj[k] = v
			}

			if len(local) == 1 {
				if k, ok := local[0].(string); ok {
					if _, present := obj[k]; !present {
						obj[k] = cty.StringVal(ref.ToString())
					}
				}
			} else if len(local) > 1 {
				if k, ok := local[0].(string); ok {
					if child, ok := obj[k]; ok {
						obj[k] = patch(local[1:], ref, child)
					} else {
						obj[k] = patch(local[1:], ref, cty.EmptyObjectVal)
					}
				}
			}
			return cty.ObjectVal(obj)
		} else if val.Type().IsTupleType() {
			// Patching counted resources.
			arr := []cty.Value{}
			for i, v := range val.AsValueSlice() {
				arr = append(arr, patch(local, ref.AddIndex(i), v))
			}
			return cty.TupleVal(arr)
		}
		return val
	}

	if attrs, ok := pa.attrs[rk]; ok {
		for attr := range attrs {
			if full, _ := StringToFullName(attr); full != nil {
				val = patch(full.Local, name, val)
			}
		}
	}
	return val
}

// Copyright 2022 Snyk Ltd
// Copyright 2021 Fugue, Inc.
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

package loader

import (
	"fmt"
	"strings"

	"github.com/snyk/unified-policy-engine/pkg/interfacetricks"
	"github.com/snyk/unified-policy-engine/pkg/models"
	"gopkg.in/yaml.v3"
)

type TfPlanDetector struct{}

func (t *TfPlanDetector) DetectFile(i InputFile, opts DetectOptions) (IACConfiguration, error) {
	if !opts.IgnoreExt && i.Ext() != ".json" {
		return nil, fmt.Errorf("File does not have .json extension: %v", i.Path())
	}
	contents, err := i.Contents()
	if err != nil {
		return nil, err
	}

	rawPlan := &tfplan_Plan{}
	if err := yaml.Unmarshal(contents, rawPlan); err != nil {
		return nil, fmt.Errorf("Failed to parse JSON file %v: %v", i.Path(), err)
	}

	if rawPlan.TerraformVersion == "" {
		return nil, fmt.Errorf("Input file is not Terraform Plan JSON: %v", i.Path())
	}

	return &tfPlan{
		path: i.Path(),
		plan: rawPlan,
	}, nil
}

func (t *TfPlanDetector) DetectDirectory(i InputDirectory, opts DetectOptions) (IACConfiguration, error) {
	return nil, nil
}

type tfPlan struct {
	path string
	plan *tfplan_Plan
}

func (l *tfPlan) RegulaInput() RegulaInput {
	return RegulaInput{
		"filepath": l.path,
		"content":  l.plan.resources(),
	}
}

func (l *tfPlan) LoadedFiles() []string {
	return []string{l.path}
}

func (l *tfPlan) Location(attributePath []string) (LocationStack, error) {
	return nil, nil
}

func (l *tfPlan) ToState() models.State {
	// TODO: This isn't implemented yet. Need to port resource view logic to Go.
	return toState("tf_plan", l.path, l.plan.resources())
}

// This (among with other types prefixed with tfplan_) matches the JSON
// format exactly.
type tfplan_Plan struct {
	TerraformVersion string                   `yaml:"terraform_version"`
	FormatVersion    string                   `yaml:"format_version"`
	PlannedValues    *tfplan_PlannedValues    `yaml:"planned_values"`
	ResourceChanges  []*tfplan_ResourceChange `yaml:"resource_changes"`
	Configuration    *tfplan_Configuration    `yaml:"configuration"`
}

type tfplan_PlannedValues struct {
	RootModule *tfplan_PlannedValuesModule `yaml:"root_module"`
}

type tfplan_PlannedValuesModule struct {
	Address      string                          `yaml:"address"`
	Resources    []*tfplan_PlannedValuesResource `yaml:"resources"`
	ChildModules []*tfplan_PlannedValuesModule   `yaml:"child_modules"`
}

type tfplan_PlannedValuesResource struct {
	Address string                 `yaml:"address"`
	Type    string                 `yaml:"type"`
	Values  map[string]interface{} `yaml:"values"`
}

type tfplan_ResourceChange struct {
	Address string                      `yaml:"address"`
	Change  tfplan_ResourceChangeChange `yaml:"change"`
}

type tfplan_ResourceChangeChange struct {
	AfterUnknown map[string]interface{} `yaml:"after_unknown"`
}

type tfplan_Configuration struct {
	RootModule *tfplan_ConfigurationModule `yaml:"root_module"`
}

type tfplan_ConfigurationModule struct {
	Resources   []*tfplan_ConfigurationResource            `yaml:"resources"`
	ModuleCalls map[string]*tfplan_ConfigurationModuleCall `yaml:"module_calls"`
}

type tfplan_ConfigurationModuleCall struct {
	Source string                      `yaml:"source"`
	Module *tfplan_ConfigurationModule `yaml:"module"`
}

type tfplan_ConfigurationResource struct {
	Address     string                                     `yaml:"address"`
	Expressions map[string]*tfplan_ConfigurationExpression `yaml:"expressions"`
}

type tfplan_ConfigurationExpression struct {
	ConstantValue *tfplan_ConfigurationExpression_ConstantValue
	References    *tfplan_ConfigurationExpression_References
	Object        map[string]tfplan_ConfigurationExpression
	Array         []tfplan_ConfigurationExpression
}

func (expr *tfplan_ConfigurationExpression) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.MappingNode {
		isConstantValue := false
		isReferences := false
		for i := 0; i < len(value.Content); i += 2 {
			var key string
			if err := value.Content[i].Decode(&key); err == nil {
				switch key {
				case "constant_value":
					isConstantValue = true
				case "references":
					isReferences = true
				}
			}
		}

		if isConstantValue {
			constantValue := tfplan_ConfigurationExpression_ConstantValue{}
			if err := value.Decode(&constantValue); err != nil {
				return err
			} else {
				expr.ConstantValue = &constantValue
				return nil
			}
		}

		if isReferences {
			references := tfplan_ConfigurationExpression_References{}
			if err := value.Decode(&references); err != nil {
				return err
			} else {
				expr.References = &references
				return nil
			}
		}

		obj := map[string]tfplan_ConfigurationExpression{}
		if err := value.Decode(&obj); err != nil {
			return err
		} else {
			expr.Object = obj
			return nil
		}
	}

	if value.Kind == yaml.SequenceNode {
		arr := []tfplan_ConfigurationExpression{}
		if err := value.Decode(&arr); err != nil {
			return err
		} else {
			expr.Array = arr
			return nil
		}
	}

	return fmt.Errorf("Unrecognized configuration expression: %v", value)
}

type tfplan_ConfigurationExpression_ConstantValue struct {
	ConstantValue interface{} `yaml:"constant_value"`
}

type tfplan_ConfigurationExpression_References struct {
	References []string `yaml:"references"`
}

func (plan *tfplan_Plan) visitModules(
	visitPlannedValuesModule func(*tfplan_PlannedValuesModule),
	visitConfigurationModule func(string, *tfplan_ConfigurationModule),
) {
	var walkPlannedValuesModule func(*tfplan_PlannedValuesModule)
	var walkConfigurationModule func(string, *tfplan_ConfigurationModule)
	walkPlannedValuesModule = func(module *tfplan_PlannedValuesModule) {
		visitPlannedValuesModule(module)
		for _, child := range module.ChildModules {
			walkPlannedValuesModule(child)
		}
	}
	walkConfigurationModule = func(path string, module *tfplan_ConfigurationModule) {
		visitConfigurationModule(path, module)
		for k, call := range module.ModuleCalls {
			childPath := "module." + k
			if path != "" {
				childPath = path + "." + childPath
			}
			walkConfigurationModule(childPath, call.Module)
		}
	}
	walkPlannedValuesModule(plan.PlannedValues.RootModule)
	walkConfigurationModule("", plan.Configuration.RootModule)
}

func (plan *tfplan_Plan) visitResources(
	visitResource func(
		string,
		*tfplan_PlannedValuesResource,
		*tfplan_ResourceChange,
		*tfplan_ConfigurationResource,
	),
) {
	plannedValueResources := map[string]*tfplan_PlannedValuesResource{}
	resourceChanges := map[string]*tfplan_ResourceChange{}
	configurationResources := map[string]*tfplan_ConfigurationResource{}
	plan.visitModules(
		func(module *tfplan_PlannedValuesModule) {
			for _, resource := range module.Resources {
				plannedValueResources[resource.Address] = resource
			}
		},
		func(path string, module *tfplan_ConfigurationModule) {
			for _, resource := range module.Resources {
				id := resource.Address
				if path != "" {
					id = path + "." + id
				}
				configurationResources[id] = resource
			}
		},
	)
	for _, resourceChange := range plan.ResourceChanges {
		resourceChanges[resourceChange.Address] = resourceChange
	}
	for k, pvResource := range plannedValueResources {
		visitResource(k,
			pvResource,
			resourceChanges[k],
			configurationResources[k],
		)
	}
}

func (resource *tfplan_ConfigurationResource) references() interface{} {
	obj := make(map[string]interface{}, len(resource.Expressions))
	for k, e := range resource.Expressions {
		if ref := e.references(); ref != nil {
			obj[k] = ref
		}
	}
	return obj
}

func (expr *tfplan_ConfigurationExpression) references() interface{} {
	if expr.ConstantValue != nil {
		return nil
	} else if expr.References != nil {
		refs := filterReferences(expr.References.References)
		if len(refs) == 1 {
			return expr.References.References[0]
		} else {
			return refs
		}
	} else if expr.Array != nil {
		arr := make([]interface{}, len(expr.Array))
		for i, e := range expr.Array {
			arr[i] = e.references()
		}
		return arr
	} else if expr.Object != nil {
		obj := make(map[string]interface{}, len(expr.Object))
		for k, e := range expr.Object {
			if ref := e.references(); ref != nil {
				obj[k] = ref
			}
		}
		return obj
	}
	return nil
}

func (plan *tfplan_Plan) resources() map[string]interface{} {
	resources := map[string]interface{}{}
	plan.visitResources(func(
		path string,
		pvr *tfplan_PlannedValuesResource,
		rc *tfplan_ResourceChange,
		cr *tfplan_ConfigurationResource,
	) {
		id := pvr.Address
		obj := map[string]interface{}{}

		// Copy attributes from planned values.
		for k, attr := range pvr.Values {
			obj[k] = attr
		}

		// Retain only references that are in AfterUnknown.
		refs := interfacetricks.Copy(rc.Change.AfterUnknown)
		refs = interfacetricks.IntersectWith(refs, cr.references(),
			func(left interface{}, r interface{}) interface{} {
				if l, ok := left.(bool); ok {
					if l {
						return r
					} else {
						return nil
					}
				}

				return interfacetricks.TopDownWalk(
					&replaceBoolTopDownWalker{
						replaceBool: func(b bool) interface{} {
							if b {
								return r
							} else {
								return nil
							}
						},
					},
					left,
				)
			},
		)

		// Merge in references
		interfacetricks.MergeWith(obj, refs, func(left interface{}, right interface{}) interface{} {
			if right == nil {
				return left
			} else {
				return right
			}
		})

		obj["_type"] = pvr.Type
		obj["id"] = id
		resources[id] = obj
	})
	return resources
}

// interfacetricks.TopDownWalker implementation that can replace a boolean.
type replaceBoolTopDownWalker struct {
	replaceBool func(bool) interface{}
}

func (w *replaceBoolTopDownWalker) WalkArray(arr []interface{}) (interface{}, bool) {
	for i, v := range arr {
		if b, ok := v.(bool); ok {
			arr[i] = w.replaceBool(b)
		}
	}
	return arr, true
}

func (w *replaceBoolTopDownWalker) WalkObject(obj map[string]interface{}) (interface{}, bool) {
	for k, v := range obj {
		if b, ok := v.(bool); ok {
			obj[k] = w.replaceBool(b)
		}
	}
	return obj, true
}

// Terraform plan format 0.2 introduced a change where the references array
// always includes both the property and its parent resource. We want to
// remove one of them (determined in should_filter) in order to maintain
// consistent behavior. The ordering is reliable - property followed by
// resource.
//
// TODO: Maybe we should just do a version check and use that instead of
// this logic.
func filterReferences(refs []string) []string {
	// Go in reverse to make use of the ordering.
	parents := []string{}
	for i := len(refs) - 1; i >= 0; i-- {
		ref := refs[i]
		foundParent := false
		for _, parent := range parents {
			if strings.HasPrefix(ref, parent) {
				foundParent = true
			}
		}
		if !foundParent {
			parents = append(parents, ref)
		}
	}
	return parents
}

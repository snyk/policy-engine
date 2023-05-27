// © 2022-2023 Snyk Limited All rights reserved.
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

package input

import (
	"fmt"
	"sort"
	"strings"

	"github.com/snyk/policy-engine/pkg/input/schemas"
	tfschemas "github.com/snyk/policy-engine/pkg/input/schemas/tf"
	"github.com/snyk/policy-engine/pkg/interfacetricks"
	"github.com/snyk/policy-engine/pkg/models"
	"gopkg.in/yaml.v3"
)

type TfPlanDetector struct{}

func (t *TfPlanDetector) DetectFile(i *File, opts DetectOptions) (IACConfiguration, error) {
	if !opts.IgnoreExt && i.Ext() != ".json" {
		return nil, fmt.Errorf("%w: %v", UnrecognizedFileExtension, i.Ext())
	}
	contents, err := i.Contents()
	if err != nil {
		return nil, err
	}

	rawPlan := &tfplan_Plan{}
	if err := yaml.Unmarshal(contents, rawPlan); err != nil {
		return nil, fmt.Errorf("%w: %v", FailedToParseInput, err)
	}

	if rawPlan.TerraformVersion == "" || rawPlan.PlannedValues == nil {
		return nil, fmt.Errorf("%w", InvalidInput)
	}

	return &tfPlan{
		path: i.Path,
		plan: rawPlan,
	}, nil
}

func (t *TfPlanDetector) DetectDirectory(i *Directory, opts DetectOptions) (IACConfiguration, error) {
	return nil, nil
}

type tfPlan struct {
	path string
	plan *tfplan_Plan
}

func (l *tfPlan) LoadedFiles() []string {
	return []string{l.path}
}

func (l *tfPlan) Location(_ []interface{}) (LocationStack, error) {
	return []Location{{Path: l.path}}, nil
}

func (l *tfPlan) ToState() models.State {
	return models.State{
		InputType:           TerraformPlan.Name,
		EnvironmentProvider: "iac",
		Meta: map[string]interface{}{
			"filepath": l.path,
		},
		Resources: groupResourcesByType(l.plan.resources(l.path)),
		Scope: map[string]interface{}{
			"filepath": l.path,
		},
	}
}

func (l *tfPlan) Errors() []error {
	return []error{}
}

func (l *tfPlan) Type() *Type {
	return TerraformPlan
}

// This (among with other types prefixed with tfplan_) matches the JSON
// format exactly.
type tfplan_Plan struct {
	TerraformVersion string                   `yaml:"terraform_version"`
	FormatVersion    string                   `yaml:"format_version"`
	PlannedValues    *tfplan_PlannedValues    `yaml:"planned_values"`
	ResourceChanges  []*tfplan_ResourceChange `yaml:"resource_changes"`
	Configuration    *tfplan_Configuration    `yaml:"configuration"`
	PriorState       *tfplan_PriorState       `yaml:"prior_state"`
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
	Mode    string                 `yaml:"mode"`
	Type    string                 `yaml:"type"`
	Values  map[string]interface{} `yaml:"values"`
}

type tfplan_ResourceChange struct {
	Address string                      `yaml:"address"`
	Change  tfplan_ResourceChangeChange `yaml:"change"`
}

type tfplan_ResourceChangeChange struct {
	// One of: "create", "no-op", "update", "delete"
	Actions      []string               `yaml:"actions"`
	AfterUnknown map[string]interface{} `yaml:"after_unknown"`
}

type tfplan_Configuration struct {
	ProviderConfig map[string]*tfplan_ProviderConfig `yaml:"provider_config"`
	RootModule     *tfplan_ConfigurationModule       `yaml:"root_module"`
}

type tfplan_ProviderConfig struct {
	VersionConstraint string                                     `yaml:"version_constraint"`
	Expressions       map[string]*tfplan_ConfigurationExpression `yaml:"expressions"`
}

type tfplan_ConfigurationModule struct {
	Outputs     map[string]tfplan_ConfigurationOutput      `yaml:"outputs"`
	Resources   []*tfplan_ConfigurationResource            `yaml:"resources"`
	ModuleCalls map[string]*tfplan_ConfigurationModuleCall `yaml:"module_calls"`
}

type tfplan_ConfigurationOutput struct {
	Expression *tfplan_ConfigurationExpression `yaml:"expression"`
}

type tfplan_ConfigurationModuleCall struct {
	Source      string                                     `yaml:"source"`
	Expressions map[string]*tfplan_ConfigurationExpression `yaml:"expressions"`
	Module      *tfplan_ConfigurationModule                `yaml:"module"`
}

type tfplan_ConfigurationResource struct {
	Address           string                                     `yaml:"address"`
	ProviderConfigKey string                                     `yaml:"provider_config_key"`
	Expressions       map[string]*tfplan_ConfigurationExpression `yaml:"expressions"`
}

type tfplan_ConfigurationExpression struct {
	ConstantValue *tfplan_ConfigurationExpression_ConstantValue
	References    *tfplan_ConfigurationExpression_References
	Object        map[string]tfplan_ConfigurationExpression
	Array         []tfplan_ConfigurationExpression
}

type tfplan_PriorState struct {
	FormatVersion    string                `yaml:"format_version"`
	TerraformVersion string                `yaml:"terraform_version"`
	Values           *tfplan_PlannedValues `yaml:"values"`
}

// Override the UnmarshalYAML for tfplan_ConfigurationExpression.  This is a
// union type that will only set exactly one of its fields.  We inspect the
// JSON structure to understand which one.
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

// Helper to iterate through all modules.
func (plan *tfplan_Plan) visitModules(
	visitPlannedValuesModule func(string, *tfplan_PlannedValuesModule),
	visitPriorStateModule func(string, *tfplan_PlannedValuesModule),
	visitConfigurationModule func(string, *tfplan_ConfigurationModule),
) {
	var walkPlannedValuesModule func(*tfplan_PlannedValuesModule)
	var walkPriorStateModule func(*tfplan_PlannedValuesModule)
	var walkConfigurationModule func(string, *tfplan_ConfigurationModule)
	walkPlannedValuesModule = func(module *tfplan_PlannedValuesModule) {
		visitPlannedValuesModule(module.Address, module)
		for _, child := range module.ChildModules {
			walkPlannedValuesModule(child)
		}
	}
	walkPriorStateModule = func(module *tfplan_PlannedValuesModule) {
		visitPriorStateModule(module.Address, module)
		for _, child := range module.ChildModules {
			walkPriorStateModule(child)
		}
	}
	walkConfigurationModule = func(path string, module *tfplan_ConfigurationModule) {
		visitConfigurationModule(path, module)
		for k, call := range module.ModuleCalls {
			childPath := joinDot(path, "module", k)
			walkConfigurationModule(childPath, call.Module)
		}
	}
	walkPlannedValuesModule(plan.PlannedValues.RootModule)
	if plan.PriorState != nil && plan.PriorState.Values != nil {
		walkPriorStateModule(plan.PriorState.Values.RootModule)
	}
	walkConfigurationModule("", plan.Configuration.RootModule)
}

// Generate a full map of outputs, assuming they reference a resource.
// This ends up looking like e.g.:
//
//	module.child1.grandchild_vpc: module.child1.module.grandchild1.grandchild_vpc
//	module.child1.module.grandchild1.grandchild_vpc: module.child1.module.grandchild1.aws_vpc.grandchild
//	parent_vpc: aws_vpc.parent
//	module.child2.var.child_vpc_id: module.child1.grandchild_vpc
//
// Then returns a function which can (recursively) resolve pointers in this
// variable map.
func (plan *tfplan_Plan) pointers() func(string) *string {
	out := map[string]string{}
	plan.visitModules(
		func(path string, module *tfplan_PlannedValuesModule) {},
		func(path string, module *tfplan_PlannedValuesModule) {},
		func(path string, module *tfplan_ConfigurationModule) {
			for key, expr := range module.Outputs {
				refs := expr.Expression.references(func(string) *string { return nil })
				if ref, ok := refs.(string); ok {
					out[joinDot(path, key)] = joinDot(path, ref)
				}
			}

			for child, call := range module.ModuleCalls {
				for key, expr := range call.Expressions {
					refs := expr.references(func(string) *string { return nil })
					if ref, ok := refs.(string); ok {
						lhs := joinDot(path, "module", child, "var", key)
						rhs := joinDot(path, ref)
						out[lhs] = rhs
					}
				}
			}
		},
	)

	return func(key string) *string {
		// Return a resolver that follows pointers, but also keep a set of
		// nodes already visited to avoid cycles.
		visited := map[string]struct{}{}
		var result *string
		for _, ok := out[key]; ok; _, ok = out[key] {
			cpy := out[key]
			result = &cpy
			visited[key] = struct{}{}
			if _, v := visited[out[key]]; v {
				return result // Avoid cycles
			}
			key = out[key]
		}
		return result
	}
}

// Helper to iterate through all resources
func (plan *tfplan_Plan) visitResources(
	visitResource func(
		module string,
		id string,
		pvr *tfplan_PlannedValuesResource,
		rc *tfplan_ResourceChange,
		cr *tfplan_ConfigurationResource,
	),
) {
	modulesByResource := map[string]string{}
	plannedValueResources := map[string]*tfplan_PlannedValuesResource{}
	priorStateResources := map[string]*tfplan_PlannedValuesResource{}
	resourceChanges := map[string]*tfplan_ResourceChange{}
	configurationResources := map[string]*tfplan_ConfigurationResource{}
	plan.visitModules(
		func(path string, module *tfplan_PlannedValuesModule) {
			for _, resource := range module.Resources {
				plannedValueResources[resource.Address] = resource
				modulesByResource[resource.Address] = path
			}
		},
		func(path string, module *tfplan_PlannedValuesModule) {
			for _, resource := range module.Resources {
				priorStateResources[resource.Address] = resource
				modulesByResource[resource.Address] = path
			}
		},
		func(path string, module *tfplan_ConfigurationModule) {
			for _, resource := range module.Resources {
				id := joinDot(path, resource.Address)
				configurationResources[id] = resource
			}
		},
	)
	for _, resourceChange := range plan.ResourceChanges {
		resourceChanges[resourceChange.Address] = resourceChange
	}

	// Resources with a count set will have an address along the likes of
	// "aws_s3_bucket.foo[3]" but the corresponding configuration resource
	// will still have an "aws_s3_bucket.foo" address.
	configurationKey := func(k string) string {
		if idx := strings.Index(k, "["); idx > 0 {
			return k[:idx]
		} else {
			return k
		}
	}

	for k, pvResource := range plannedValueResources {
		visitResource(
			modulesByResource[k],
			k,
			pvResource,
			resourceChanges[k],
			configurationResources[configurationKey(k)],
		)
	}

	// Also consider prior_state data resources.  These have the same format
	// as planned values.
	for k, priorStateResource := range priorStateResources {
		if _, ok := plannedValueResources[k]; !ok {
			if strings.HasPrefix(k, "data.") {
				visitResource(
					modulesByResource[k],
					k,
					priorStateResource,
					resourceChanges[k],
					configurationResources[configurationKey(k)],
				)
			}
		}
	}
}

// Figure out which variables or resources are referenced.  A resolver function
// can be passed in.
func (resource *tfplan_ConfigurationResource) references(resolve func(string) *string) interface{} {
	obj := make(map[string]interface{}, len(resource.Expressions))
	for k, e := range resource.Expressions {
		if ref := e.references(resolve); ref != nil {
			obj[k] = ref
		}
	}
	return obj
}

// Figure out which variables or resources are referenced.  A resolver function
// can be passed in.
func (expr *tfplan_ConfigurationExpression) references(resolve func(string) *string) interface{} {
	if expr.ConstantValue != nil {
		return nil
	} else if expr.References != nil {
		refs := filterReferences(expr.References.References)
		resolved := make([]string, len(refs))
		for i, ref := range refs {
			if val := resolve(ref); val != nil {
				resolved[i] = *val
			} else {
				resolved[i] = ref
			}
		}
		if len(resolved) == 1 {
			return resolved[0]
		} else {
			return resolved
		}
	} else if expr.Array != nil {
		arr := make([]interface{}, len(expr.Array))
		for i, e := range expr.Array {
			arr[i] = e.references(resolve)
		}
		return arr
	} else if expr.Object != nil {
		obj := make(map[string]interface{}, len(expr.Object))
		for k, e := range expr.Object {
			if ref := e.references(resolve); ref != nil {
				obj[k] = ref
			}
		}
		return obj
	}
	return nil
}

// If a configuration expression consists only of constant values, we can try to
// evaluate it.
func (expr *tfplan_ConfigurationExpression) evalConstantValue() interface{} {
	if expr.ConstantValue != nil {
		return expr.ConstantValue.ConstantValue
	} else if expr.References != nil {
		return nil
	} else if expr.Array != nil {
		arr := make([]interface{}, len(expr.Array))
		for i, e := range expr.Array {
			arr[i] = e.evalConstantValue()
		}
		return arr
	} else if expr.Object != nil {
		obj := make(map[string]interface{}, len(expr.Object))
		for k, e := range expr.Object {
			if cv := e.evalConstantValue(); cv != nil {
				obj[k] = cv
			}
		}
		return obj
	}
	return nil
}

// Main entry point to convert this to an input state.
func (plan *tfplan_Plan) resources(resourceNamespace string) []models.ResourceState {
	// Calculate outputs
	resolveGlobally := plan.pointers()

	resources := []models.ResourceState{}
	plan.visitResources(func(
		module string,
		path string,
		pvr *tfplan_PlannedValuesResource,
		rc *tfplan_ResourceChange,
		cr *tfplan_ConfigurationResource,
	) {
		id := pvr.Address
		attributes := map[string]interface{}{}

		// Copy attributes from planned values.
		for k, attr := range pvr.Values {
			attributes[k] = attr
		}

		// Retain only references that are in AfterUnknown.
		if rc != nil && cr != nil {
			refs := interfacetricks.Copy(rc.Change.AfterUnknown)
			refs = interfacetricks.IntersectWith(
				refs,
				cr.references(func(variable string) *string {
					// When resolving references, take the module name into account.
					qualified := joinDot(module, variable)
					if result := resolveGlobally(qualified); result != nil {
						return result
					} else {
						return &qualified
					}
				}),
				// Intersect using a function that replaces all the "true"s on the
				// left hand side (in the AfterUnknown structure) with the
				// references we found.
				func(left interface{}, r interface{}) interface{} {
					// There's a bool in the AfterUnknown so just return the
					// references if true.
					if l, ok := left.(bool); ok {
						if l {
							return r
						} else {
							return nil
						}
					}

					// There's an array/object of booleans, use interfacetricks
					// to construct a tree of the same shape but containing
					// the references rather than "true".
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
			interfacetricks.MergeWith(attributes, refs, func(left interface{}, right interface{}) interface{} {
				if right == nil {
					return left
				} else {
					return right
				}
			})
		}

		meta := map[string]interface{}{}
		metaTerraform := map[string]interface{}{}
		metaTfplan := map[string]interface{}{}
		if cr != nil {
			if config, ok := plan.Configuration.ProviderConfig[cr.ProviderConfigKey]; ok {
				if config.VersionConstraint != "" {
					metaTerraform["provider_version_constraint"] = config.VersionConstraint
				}

				conf := map[string]interface{}{}
				for k, ec := range config.Expressions {
					if ev := ec.evalConstantValue(); ev != nil {
						conf[k] = ev
					}
				}
				if len(conf) > 0 {
					metaTerraform["provider_config"] = conf
				}
				if region, ok := conf["region"].(string); ok {
					// Add meta.region if present
					meta["region"] = region
				}
			}
		}
		if rc != nil {
			resourceActions := []interface{}{}
			for _, action := range rc.Change.Actions {
				resourceActions = append(resourceActions, action)
			}
			metaTfplan["resource_actions"] = resourceActions
		}
		if len(metaTerraform) > 0 {
			meta["terraform"] = metaTerraform
		}
		if len(metaTfplan) > 0 {
			meta["tfplan"] = metaTfplan
		}

		var resourceType string
		if pvr.Mode == "data" {
			resourceType = strings.Join([]string{pvr.Mode, pvr.Type}, ".")
		} else {
			resourceType = pvr.Type
		}

		attributes = schemas.ApplyObject(attributes, tfschemas.GetSchema(resourceType))

		model := models.ResourceState{
			Id:           id,
			ResourceType: resourceType,
			Namespace:    resourceNamespace,
			Attributes:   attributes,
			Meta:         meta,
		}
		model.Tags = tfExtractTags(model)
		resources = append(resources, model)
	})

	return resources
}

// interfacetricks.TopDownWalker implementation that can replace a boolean.
type replaceBoolTopDownWalker struct {
	replaceBool func(bool) interface{}
}

func (*replaceBoolTopDownWalker) WalkArray(arr []interface{}) (interface{}, bool) {
	return arr, true
}

func (*replaceBoolTopDownWalker) WalkObject(obj map[string]interface{}) (interface{}, bool) {
	return obj, true
}

func (*replaceBoolTopDownWalker) WalkString(s string) (interface{}, bool) {
	return s, false
}

func (w *replaceBoolTopDownWalker) WalkBool(b bool) (interface{}, bool) {
	return w.replaceBool(b), false
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
	prefixes := map[string]struct{}{}
	for _, ref := range refs {
		if parts := strings.Split(ref, "."); len(parts) > 0 {
			switch parts[0] {
			case "module":
				if len(parts) >= 3 {
					prefixes[strings.Join(parts[:3], ".")] = struct{}{}
				}
			case "data":
				if len(parts) >= 3 {
					prefixes[strings.Join(parts[:3], ".")] = struct{}{}
				}
			case "var":
				prefixes[ref] = struct{}{}
			default:
				if len(parts) >= 2 {
					prefixes[strings.Join(parts[:2], ".")] = struct{}{}
				}
			}
		}
	}

	// Sort before returning
	resources := []string{}
	for k := range prefixes {
		resources = append(resources, k)
	}
	sort.Strings(resources)
	return resources
}

func joinDot(parts ...string) string {
	result := ""
	for _, part := range parts {
		if part != "" {
			if result == "" {
				result = part
			} else {
				result = result + "." + part
			}
		}
	}
	return result
}

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
	"encoding/json"
	"fmt"
	"strings"

	"github.com/snyk/policy-engine/pkg/input/arm"
	"github.com/snyk/policy-engine/pkg/interfacetricks"
	"github.com/snyk/policy-engine/pkg/models"
)

var validArmExts map[string]bool = map[string]bool{
	".json": true,
}

type ArmDetector struct{}

func (c *ArmDetector) DetectFile(i *File, opts DetectOptions) (IACConfiguration, error) {
	if !opts.IgnoreExt && !validArmExts[i.Ext()] {
		return nil, fmt.Errorf("%w: %v", UnrecognizedFileExtension, i.Ext())
	}
	contents, err := i.Contents()
	if err != nil {
		return nil, fmt.Errorf("%w", UnableToReadFile)
	}

	template := arm_Template{}
	if err := json.Unmarshal(contents, &template); err != nil {
		return nil, fmt.Errorf("%w: %v", FailedToParseInput, err)
	}

	if template.Schema == "" || template.Resources == nil {
		return nil, fmt.Errorf("%w", InvalidInput)
	}

	// Don't consider source code locations essential.
	source, _ := LoadSourceInfoNode(contents)

	// Prepare evaluator to use.
	evalCtx := &arm.EvaluationContext{
		Functions: arm.DiscoveryBuiltinFunctions(
			template.variables(),
		),
	}

	// Create a map of resource ID to discovered resources.  This is necessary
	// for source code locations.
	discovered := template.resources(evalCtx)
	resourceSet := map[string]struct{}{}
	for _, resource := range discovered {
		resourceSet[resource.name.String()] = struct{}{}
	}

	// Extend evaluator.
	evalCtx.Functions = arm.AllBuiltinFunctions(
		template.variables(),
		resourceSet,
	)

	resources := map[string]arm_Resource{}
	for _, resource := range discovered {
		resources[resource.name.String()] = resource.process(evalCtx)
	}

	path := i.Path
	cfg := &armConfiguration{
		path:      path,
		source:    source,
		resources: resources,
	}

	return cfg, nil
}

func (c *ArmDetector) DetectDirectory(i *Directory, opts DetectOptions) (IACConfiguration, error) {
	return nil, nil
}

type armConfiguration struct {
	path      string
	source    *SourceInfoNode
	resources map[string]arm_Resource
}

func (l *armConfiguration) ToState() models.State {
	resources := []models.ResourceState{}
	for _, resource := range l.resources {
		resources = append(resources, resource.state(l.path))
	}
	return models.State{
		InputType:           Arm.Name,
		EnvironmentProvider: "iac",
		Meta: map[string]interface{}{
			"filepath": l.path,
		},
		Resources: groupResourcesByType(resources),
	}
}

func (l *armConfiguration) Location(path []interface{}) (LocationStack, error) {
	// Format is {resourceNamespace, resourceType, resourceId, attributePath...}
	if l.source == nil || len(path) < 3 {
		return nil, nil
	}

	resourceId, ok := path[2].(string)
	if !ok {
		return nil, fmt.Errorf(
			"%w: Expected string resource ID in path: %v",
			UnableToResolveLocation,
			path,
		)
	}

	dr, ok := l.resources[resourceId]
	if !ok {
		return nil, fmt.Errorf(
			"%w: Unable to find resource with ID: %s",
			UnableToResolveLocation,
			resourceId,
		)
	}

	fullPath := make([]interface{}, len(dr.path))
	copy(fullPath, dr.path)
	fullPath = append(fullPath, path[3:]...)
	node, err := l.source.GetPath(fullPath)
	line, column := node.Location()
	return []Location{{Path: l.path, Line: line, Col: column}}, err
}

func (l *armConfiguration) LoadedFiles() []string {
	return []string{l.path}
}

func (l *armConfiguration) Errors() []error {
	errs := []error{}
	for _, resource := range l.resources {
		errs = append(errs, resource.errors...)
	}
	return errs
}

func (l *armConfiguration) Type() *Type {
	return Arm
}

type arm_Template struct {
	Schema         string                   `json:"$schema"`
	ContentVersion string                   `json:"contentVersion"`
	Resources      []map[string]interface{} `json:"resources"`
	Variables      map[string]interface{}   `json:"variables"`
}

type arm_DiscoveredResource struct {
	name   arm_Name
	path   []interface{}
	data   map[string]interface{}
	errors []error
}

type arm_Resource struct {
	name       arm_Name
	path       []interface{}
	properties map[string]interface{}
	tags       map[string]string
	leftovers  map[string]interface{} // Not name, tags, properties...
	errors     []error
}

func (template *arm_Template) resources(
	evalCtx *arm.EvaluationContext,
) []arm_DiscoveredResource {
	output := []arm_DiscoveredResource{}

	// Recursive worker
	var visit func([]interface{}, *arm_Name, map[string]interface{})
	visit = func(
		path []interface{},
		parentName *arm_Name,
		resource map[string]interface{},
	) {
		parsed := struct {
			Name      string                   `json:"name"`
			Type      string                   `json:"type"`
			Resources []map[string]interface{} `json:"resources"`
		}{}
		errs := interfacetricks.Extract(resource, &parsed)

		// Delete parsed fields
		data := interfacetricks.CopyObject(resource)
		delete(data, "name")
		delete(data, "type")
		delete(data, "resources")

		// Evaluate name and type.
		evaluator := &evalWalker{evalCtx: evalCtx}
		nameVal := interfacetricks.TopDownWalk(evaluator, parsed.Name)
		errs = append(errs, interfacetricks.Extract(nameVal, &parsed.Name)...)
		typeVal := interfacetricks.TopDownWalk(evaluator, parsed.Type)
		errs = append(errs, interfacetricks.Extract(typeVal, &parsed.Type)...)
		errs = append(errs, evaluator.errors...)

		// Extend or construct name.
		name := parseArmName(parsed.Type, parsed.Name)
		if parentName != nil {
			// We are nested under some parent.
			name = parentName.Child(parsed.Type, parsed.Name)
		}

		// Add discovered resource.
		discovered := arm_DiscoveredResource{
			name:   name,
			path:   path,
			data:   data,
			errors: errs,
		}
		output = append(output, discovered)

		// Recurse on children.
		for i, child := range parsed.Resources {
			childPath := make([]interface{}, len(path))
			copy(childPath, path)
			childPath = append(childPath, "resources")
			childPath = append(childPath, i)
			visit(childPath, &name, child)
		}
	}

	for i, top := range template.Resources {
		visit([]interface{}{"resources", i}, nil, top)
	}
	return output
}

// For now, ensure we only return supported types. In the future, this might be
// part of a multi-pass parse flow in order to evaluate expressions in variable
// definitions, before evaluating expressions that use those results.
//
// When adding more types, please ensure that we have parser support for them in
// pkg/input/arm.
func (template *arm_Template) variables() map[string]interface{} {
	processed := map[string]interface{}{}
	for k, v := range template.Variables {
		switch typedVal := v.(type) {
		case string:
			if !arm.IsTemplateExpression(typedVal) {
				processed[k] = v
			}
		default:
		}
	}
	return processed
}

func (resource arm_DiscoveredResource) process(
	evalCtx *arm.EvaluationContext,
) arm_Resource {
	errs := []error{}
	errs = append(errs, resource.errors...)
	parsed := struct {
		Properties map[string]interface{} `json:"properties"`
		Tags       interface{}            `json:"tags"`
	}{}
	errs = append(errs, interfacetricks.Extract(resource.data, &parsed)...)

	leftovers := interfacetricks.CopyObject(resource.data)
	delete(leftovers, "properties")
	delete(leftovers, "tags")

	// Evaluate properties, tags and leftovers.
	evaluator := &evalWalker{evalCtx: evalCtx}
	properties := map[string]interface{}{}
	for k, v := range parsed.Properties {
		properties[k] = interfacetricks.TopDownWalk(evaluator, v)
	}
	tags := map[string]string{}
	tagsValue := interfacetricks.TopDownWalk(evaluator, parsed.Tags)
	errs = append(errs, interfacetricks.Extract(tagsValue, &tags)...)
	for k, v := range leftovers {
		leftovers[k] = interfacetricks.TopDownWalk(evaluator, v)
	}
	errs = append(errs, evaluator.errors...)

	return arm_Resource{
		name:       resource.name,
		path:       resource.path,
		properties: properties,
		tags:       tags,
		leftovers:  leftovers,
		errors:     errs,
	}
}

func (resource arm_Resource) state(namespace string) models.ResourceState {
	attributes := map[string]interface{}{}
	for k, attr := range resource.leftovers {
		attributes[k] = attr
	}
	properties := map[string]interface{}{}
	for k, attr := range resource.properties {
		properties[k] = attr
	}
	attributes["properties"] = properties
	meta := map[string]interface{}{}
	if parent := resource.name.Parent(); parent != nil {
		armMeta := map[string]interface{}{}
		armMeta["parent_id"] = parent.String()
		attributes["_parent_id"] = parent.String() // Backwards-compat :-(
		meta["arm"] = armMeta
	}

	state := models.ResourceState{
		Namespace:    namespace,
		Id:           resource.name.String(),
		ResourceType: resource.name.Type(),
		Attributes:   attributes,
		Meta:         meta,
	}

	if len(resource.tags) > 0 {
		state.Tags = resource.tags
	}

	return state
}

// Microsoft.Network/virtualNetworks/VNet1/subnets/Subnet1 is represented by:
//
// - service: Microsoft.Network
// - types: [virtualNetworks, subnets]
// - names: VNet1, Subnet1
//
// TODO: this should probably be moved to the pkg/input/arm package, and some
// of the builtins can maybe then use this as well.
type arm_Name struct {
	service string
	types   []string
	names   []string
}

func parseArmName(typeString string, nameString string) arm_Name {
	name := arm_Name{}
	types := strings.Split(typeString, "/")
	if len(types) > 0 {
		name.service = types[0]
		name.types = types[1:]
	}
	name.names = strings.Split(nameString, "/")
	return name
}

func (n arm_Name) Type() string {
	return n.service + "/" + strings.Join(n.types, "/")
}

func (n arm_Name) String() string {
	str := n.service
	for i := 0; i < len(n.types) && i < len(n.names); i++ {
		str = str + "/" + n.types[i] + "/" + n.names[i]
	}
	return str
}

// Extends a parent name to a child name by adding types and names, e.g.
//
//	Microsoft.Network/virtualNetworks/subnets + VNet1/Subnet1 =
//	-> Microsoft.Network/virtualNetworks/VNet1/subnets/Subnet1
func (parent arm_Name) Child(typeString string, nameString string) arm_Name {
	child := arm_Name{}
	child.service = parent.service

	types := strings.Split(typeString, "/")
	child.types = make([]string, len(parent.types)+len(types))
	copy(child.types, parent.types)
	copy(child.types[len(parent.types):], types)

	names := strings.Split(nameString, "/")
	child.names = make([]string, len(parent.names)+len(names))
	copy(child.names, parent.names)
	copy(child.names[len(parent.names):], names)
	return child
}

// Returns the parent name of a child name, or nil if this name has
// no parent.
func (child arm_Name) Parent() *arm_Name {
	if len(child.types) <= 1 || len(child.names) <= 1 {
		return nil
	}

	parent := arm_Name{}
	parent.service = child.service

	parent.types = make([]string, len(child.types)-1)
	copy(parent.types, child.types)

	parent.names = make([]string, len(child.names)-1)
	copy(parent.names, child.names)

	return &parent
}

// TopDownInterfaceWalker implementation to find and replace resource references
// for ARM and store errors.
type evalWalker struct {
	evalCtx *arm.EvaluationContext
	errors  []error
}

func (*evalWalker) WalkArray(arr []interface{}) (interface{}, bool) {
	return arr, true
}

func (*evalWalker) WalkObject(obj map[string]interface{}) (interface{}, bool) {
	return obj, true
}

func (resolver *evalWalker) WalkString(s string) (interface{}, bool) {
	evaluatedExpression, err := resolver.evalCtx.EvaluateTemplateString(s)
	if err != nil {
		resolver.errors = append(resolver.errors, err)
		return s, false
	}
	return evaluatedExpression, false
}

func (*evalWalker) WalkBool(b bool) (interface{}, bool) {
	return b, false
}

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
	"regexp"
	"strings"

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

	template := &arm_Template{}
	if err := json.Unmarshal(contents, &template); err != nil {
		return nil, fmt.Errorf("%w: %v", FailedToParseInput, err)
	}

	if template.Schema == "" || template.Resources == nil {
		return nil, fmt.Errorf("%w", InvalidInput)
	}

	// Don't consider source code locations essential.
	source, _ := LoadSourceInfoNode(contents)

	// Create a map of resource ID to discovered resources.  This is necessary
	// for source code locations.
	discovered := map[string]arm_DiscoverResource{}
	for _, d := range template.discover() {
		discovered[d.name.String()] = d
	}

	path := i.Path
	return &armConfiguration{
		path:       path,
		template:   template,
		discovered: discovered,
		source:     source,
	}, nil
}

func (c *ArmDetector) DetectDirectory(i *Directory, opts DetectOptions) (IACConfiguration, error) {
	return nil, nil
}

type armConfiguration struct {
	path       string
	template   *arm_Template
	discovered map[string]arm_DiscoverResource
	source     *SourceInfoNode
}

func (l *armConfiguration) ToState() models.State {
	// Set of all existing resources for the resolver.
	resourceSet := map[string]struct{}{}
	for id := range l.discovered {
		resourceSet[id] = struct{}{}
	}
	refResolver := arm_ReferenceResolver{
		resources: resourceSet,
	}

	// Process resources
	resources := []models.ResourceState{}
	for _, d := range l.discovered {
		resource := d.process(&refResolver)
		resource.Namespace = l.path
		resources = append(resources, resource)
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

	dr, ok := l.discovered[resourceId]
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
	for _, resource := range l.discovered {
		errs = append(errs, resource.errors()...)
	}
	return errs
}

func (l *armConfiguration) Type() *Type {
	return Arm
}

type arm_Template struct {
	Schema         string         `json:"$schema"`
	ContentVersion string         `json:"contentVersion"`
	Resources      []arm_Resource `json:"resources"`
}

type arm_Resource struct {
	Type       string                 `json:"type"`
	Name       string                 `json:"name"`
	Properties map[string]interface{} `json:"properties"`
	Tags       arm_Tags               `json:"tags"`
	Resources  []arm_Resource         `json:"resources"`
	// OtherAttributes is a container for all other attributes that we're not
	// capturing above.
	OtherAttributes map[string]interface{} `json:"-"`
}

// Type alias to avoid infinite recursion
type _arm_Resource arm_Resource

func (r *arm_Resource) UnmarshalJSON(bs []byte) error {
	// We're using a custom unmarshal function here so that we can support all the
	// possible resource attributes without explicitly adding them to the
	// arm_Resource struct. The way this works is that we unmarshal the JSON twice:
	// first into the arm_Resource struct and second into the OtherAttributes map. By
	// using an alias for the arm_Resource type, we prevent this function from calling
	// itself when we unmarshal into the struct.
	resource := _arm_Resource{}
	if err := json.Unmarshal(bs, &resource); err != nil {
		return err
	}
	if err := json.Unmarshal(bs, &resource.OtherAttributes); err != nil {
		return err
	}

	// Delete attributes that we've already captured in the parent struct
	delete(resource.OtherAttributes, "type")
	delete(resource.OtherAttributes, "name")
	delete(resource.OtherAttributes, "properties")
	delete(resource.OtherAttributes, "tags")
	delete(resource.OtherAttributes, "resources")

	// point r to our parsed resource
	*r = arm_Resource(resource)

	return nil
}

func (r *arm_Resource) errors() []error {
	if r.Tags.err != nil {
		return []error{r.Tags.err}
	}
	return nil
}

// arm_Tags is simply there to help with unmarshaling of tags.
type arm_Tags struct {
	err  error
	tags map[string]string
}

func (t *arm_Tags) UnmarshalJSON(bs []byte) error {
	// Tags should always be an object.  However, we currently don't support
	// ARM functions, which can make the tags look like a string, e.g.:
	//
	//     "tags": "[parameters('tagValues')]"
	//
	// We need to make sure we treat this as a warning rather than an error.
	t.tags = map[string]string{}
	err := json.Unmarshal(bs, &t.tags)
	if err != nil {
		t.err = fmt.Errorf("%w: failed to parse tags: %v", FailedToParseInput, err)
	}
	return nil
}

// A resource together with its JSON path and name metadata.  This allows us to
// iterate them and obtain a flat list before we actually process them.
type arm_DiscoverResource struct {
	name     arm_Name
	path     []interface{}
	resource arm_Resource
}

func (t arm_Template) discover() []arm_DiscoverResource {
	discovered := []arm_DiscoverResource{}
	var visit func([]interface{}, *arm_Name, arm_Resource)
	visit = func(
		path []interface{},
		parentName *arm_Name,
		resource arm_Resource,
	) {
		// Extend or construct name.
		name := parseArmName(resource.Type, resource.Name)
		if parentName != nil {
			// We are nested under some parent.
			name = parentName.Child(resource.Type, resource.Name)
		}

		// Add discovered resource.
		discovered = append(discovered, arm_DiscoverResource{
			name:     name,
			path:     path,
			resource: resource,
		})

		// Recurse on children.
		for i, child := range resource.Resources {
			childPath := make([]interface{}, len(path))
			copy(childPath, path)
			childPath = append(childPath, "resources")
			childPath = append(childPath, i)
			visit(childPath, &name, child)
		}
	}

	for i, top := range t.Resources {
		visit([]interface{}{"resources", i}, nil, top)
	}
	return discovered
}

func (d arm_DiscoverResource) process(
	refResolver *arm_ReferenceResolver,
) models.ResourceState {
	r := d.resource

	attributes := map[string]interface{}{}
	for k, attr := range r.OtherAttributes {
		updated := interfacetricks.TopDownWalk(refResolver, interfacetricks.Copy(attr))
		attributes[k] = updated
	}
	properties := map[string]interface{}{}
	for k, attr := range r.Properties {
		updated := interfacetricks.TopDownWalk(refResolver, interfacetricks.Copy(attr))
		properties[k] = updated
	}
	attributes["properties"] = properties
	meta := map[string]interface{}{}
	if parent := d.name.Parent(); parent != nil {
		armMeta := map[string]interface{}{}
		armMeta["parent_id"] = parent.String()
		attributes["_parent_id"] = parent.String() // Backwards-compat :-(
		meta["arm"] = armMeta
	}

	state := models.ResourceState{
		Id:           d.name.String(),
		ResourceType: d.name.Type(),
		Attributes:   attributes,
		Meta:         meta,
	}

	if len(r.Tags.tags) > 0 {
		state.Tags = r.Tags.tags
	}

	return state
}

func (d arm_DiscoverResource) errors() []error {
	return d.resource.errors()
}

// Microsoft.Network/virtualNetworks/VNet1/subnets/Subnet1 is represented by:
//
// - service: Microsoft.Network
// - types: [virtualNetworks, subnets]
// - names: VNet1, Subnet1
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
// for ARM.
type arm_ReferenceResolver struct {
	// Set of present resources.
	resources map[string]struct{}
}

func (*arm_ReferenceResolver) WalkArray(arr []interface{}) (interface{}, bool) {
	return arr, true
}

func (*arm_ReferenceResolver) WalkObject(obj map[string]interface{}) (interface{}, bool) {
	return obj, true
}

func (resolver *arm_ReferenceResolver) WalkString(s string) (interface{}, bool) {
	if strings.HasPrefix(s, "[") {
		re := regexp.MustCompile(`[\[\]()',[:space:]]+`)
		rawTokens := re.Split(s, -1)
		tokens := []string{}
		for _, t := range rawTokens {
			if t != "" {
				tokens = append(tokens, t)
			}
		}

		if len(tokens) >= 3 && tokens[0] == "resourceId" {
			typeStr := tokens[1]
			nameStr := strings.Join(tokens[2:], "/")
			ref := parseArmName(typeStr, nameStr).String()
			if _, ok := resolver.resources[ref]; ok {
				return ref, false
			}
		}
	}

	return s, false
}

func (*arm_ReferenceResolver) WalkBool(b bool) (interface{}, bool) {
	return b, false
}

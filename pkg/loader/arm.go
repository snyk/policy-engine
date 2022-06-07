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
	"encoding/json"
	"fmt"
	"strings"

	"github.com/snyk/unified-policy-engine/pkg/inputs"
	"github.com/snyk/unified-policy-engine/pkg/models"
)

var validArmExts map[string]bool = map[string]bool{
	".json": true,
}

type ArmDetector struct{}

func (c *ArmDetector) DetectFile(i InputFile, opts DetectOptions) (IACConfiguration, error) {
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

	path := i.Path()
	return &armConfiguration{
		path:     path,
		template: template,
	}, nil
}

func (c *ArmDetector) DetectDirectory(i InputDirectory, opts DetectOptions) (IACConfiguration, error) {
	return nil, nil
}

type armConfiguration struct {
	path     string
	template *arm_Template
	source   *SourceInfoNode
}

func (l *armConfiguration) ToState() models.State {
	resources := map[string]models.ResourceState{}
	for _, resource := range l.template.resources() {
		resource.Namespace = l.path
		resources[resource.Id] = resource
	}

	return models.State{
		InputType:           inputs.Arm.Name,
		EnvironmentProvider: "iac",
		Meta: map[string]interface{}{
			"filepath": l.path,
		},
		Resources: groupResourcesByType(resources),
	}
}

func (l *armConfiguration) Location(path []interface{}) (LocationStack, error) {
	return nil, nil
}

func (l *armConfiguration) LoadedFiles() []string {
	return []string{l.path}
}

type arm_Template struct {
	Schema         string         `json:"$schema"`
	ContentVersion string         `json:"contentVersion"`
	Resources      []arm_Resource `json:"resources"`
}

type arm_Resource struct {
	Type       string                 `json:"type"`
	ApiVersion string                 `json:"apiVersion"`
	Name       string                 `json:"name"`
	Location   string                 `json:"location"`
	Properties map[string]interface{} `json:"properties"`
	Tags       map[string]string      `json:"tags"`
	Resources  []arm_Resource         `json:"resources"`
}

func (t arm_Template) resources() []models.ResourceState {
	all := []models.ResourceState{}
	for _, top := range t.Resources {
		all = append(all, top.resources(nil)...)
	}
	return all
}

func (r arm_Resource) resources(
	parent *arm_Name, // Name of the parent, nil if top-level
) []models.ResourceState {
	// Extend or construct name.
	name := parseArmName(r.Type, r.Name)
	if parent != nil {
		// We are nested under some parent.
		name = parent.Child(r.Type, r.Name)
	} else {
		// Not nested but our name may refer to a parent.
		parent = name.Parent()
	}

	attributes := map[string]interface{}{}
	attributes["properties"] = r.Properties
	if r.ApiVersion != "" {
		attributes["apiVersion"] = r.ApiVersion
	}
	if r.Location != "" {
		attributes["location"] = r.Location
	}

	meta := map[string]interface{}{}
	if parent != nil {
		armMeta := map[string]interface{}{}
		armMeta["parent_id"] = parent.String()
		meta["arm"] = armMeta
	}

	this := models.ResourceState{
		Id:           name.String(),
		ResourceType: name.Type(),
		Attributes:   attributes,
		Meta:         meta,
	}

	if len(r.Tags) > 0 {
		this.Tags = r.Tags
	}

	list := []models.ResourceState{this}
	for _, child := range r.Resources {
		list = append(list, child.resources(&name)...)
	}

	return list
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
//     Microsoft.Network/virtualNetworks/subnets + VNet1/Subnet1 =
//     -> Microsoft.Network/virtualNetworks/VNet1/subnets/Subnet1
//
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

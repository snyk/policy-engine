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
	"regexp"
	"strings"

	"github.com/snyk/unified-policy-engine/pkg/inputtypes"
	"github.com/snyk/unified-policy-engine/pkg/interfacetricks"
	"github.com/snyk/unified-policy-engine/pkg/models"
	"gopkg.in/yaml.v3"
)

var validCfnExts map[string]bool = map[string]bool{
	".yaml": true,
	".yml":  true,
	".json": true,
}

type CfnDetector struct{}

func (c *CfnDetector) DetectFile(i InputFile, opts DetectOptions) (IACConfiguration, error) {
	if !opts.IgnoreExt && !validCfnExts[i.Ext()] {
		return nil, fmt.Errorf("File does not have .yaml, .yml, or .json extension: %v", i.Path())
	}
	contents, err := i.Contents()
	if err != nil {
		return nil, err
	}

	template := &cfnTemplate{}
	if err := yaml.Unmarshal(contents, &template); err != nil || template == nil {
		return nil, fmt.Errorf("Failed to parse file as YAML or JSON %v: %v", i.Path(), err)
	}

	if template.AWSTemplateFormatVersion == nil && template.Resources == nil {
		return nil, fmt.Errorf("Input file is not a CloudFormation template: %v", i.Path())
	}

	path := i.Path()
	source, err := LoadSourceInfoNode(contents)
	if err != nil {
		source = nil // Don't consider source code locations essential.
	}

	return &cfnConfiguration{
		path:      path,
		template:  *template,
		source:    source,
		resources: template.resources(),
	}, nil
}

func (c *CfnDetector) DetectDirectory(i InputDirectory, opts DetectOptions) (IACConfiguration, error) {
	return nil, nil
}

type cfnTemplate struct {
	AWSTemplateFormatVersion interface{}             `yaml:"AWSTemplateFormatVersion"`
	Parameters               map[string]cfnParameter `yaml:"Parameters"`
	Resources                map[string]cfnResource  `yaml:"Resources"`
}

type cfnParameter struct {
	Default       interface{}   `yaml:"Default"`
	AllowedValues []interface{} `yaml:"AllowedValues"`
}

type cfnResource struct {
	Type       string `yaml:"Type"`
	Properties cfnMap `yaml:"Properties"`
}

// This is a type that has a custom UnmarshalYAML that we use to do some
// decoding.
type cfnMap struct {
	Contents map[string]interface{}
}

func (t *cfnMap) UnmarshalYAML(node *yaml.Node) error {
	contents, err := decodeMap(node)
	if err != nil {
		return err
	}
	t.Contents = contents
	return nil
}

func (tmpl *cfnTemplate) resources() map[string]interface{} {
	parameters := map[string]interface{}{}
	for k, param := range tmpl.Parameters {
		if param.Default != nil {
			parameters[k] = param.Default
		} else if len(param.AllowedValues) > 0 {
			parameters[k] = param.AllowedValues[0]
		}
	}

	resolver := cfnReferenceResolver{
		parameters: parameters,
	}

	resources := map[string]interface{}{}
	for resourceId, resource := range tmpl.Resources {
		object := map[string]interface{}{}
		for k, attribute := range resource.Properties.Contents {
			object[k] = interfacetricks.TopDownWalk(&resolver, attribute)
			object["id"] = resourceId
			object["_type"] = resource.Type
		}

		resources[resourceId] = object
	}
	return resources
}

type cfnConfiguration struct {
	path      string
	template  cfnTemplate
	source    *SourceInfoNode
	resources map[string]interface{}
}

func (l *cfnConfiguration) ToState() models.State {
	return toState(inputtypes.CloudFormation.Name, l.path, l.resources)
}

func (l *cfnConfiguration) Location(path []interface{}) (LocationStack, error) {
	// Format is {resourceType, resourceId, attributePath...}
	if l.source == nil || len(path) < 2 {
		return nil, nil
	}

	resourceId, ok := path[1].(string)
	if !ok {
		return nil, fmt.Errorf("Expected string resource ID in path")
	}

	fullPath := []interface{}{"Resources", resourceId}
	if len(path) > 2 {
		fullPath = append(fullPath, "Properties")
		fullPath = append(fullPath, path[2:]...)
	}
	node, err := l.source.GetPath(fullPath)
	line, column := node.Location()
	return []Location{{Path: l.path, Line: line, Col: column}}, err
}

func (l *cfnConfiguration) LoadedFiles() []string {
	return []string{l.path}
}

func decodeMap(node *yaml.Node) (map[string]interface{}, error) {
	if len(node.Content)%2 != 0 {
		return nil, fmt.Errorf("Malformed map at line %v, col %v", node.Line, node.Column)
	}

	m := map[string]interface{}{}

	for i := 0; i < len(node.Content); i += 2 {
		keyNode := node.Content[i]
		valNode := node.Content[i+1]

		if keyNode.Kind != yaml.ScalarNode || keyNode.Tag != "!!str" {
			return nil, fmt.Errorf("Malformed map key at line %v, col %v", keyNode.Line, keyNode.Column)
		}

		var key string

		if err := keyNode.Decode(&key); err != nil {
			return nil, fmt.Errorf("Failed to decode map key: %v", err)
		}

		val, err := decodeNode(valNode)

		if err != nil {
			return nil, fmt.Errorf("Failed to decode map val: %v", err)
		}

		m[key] = val
	}

	return m, nil
}

func decodeSeq(node *yaml.Node) ([]interface{}, error) {
	s := []interface{}{}
	for _, child := range node.Content {
		i, err := decodeNode(child)
		if err != nil {
			return nil, fmt.Errorf("Error decoding sequence item at line %v, col %v", child.Line, child.Column)
		}
		s = append(s, i)
	}

	return s, nil
}

var intrinsicFns map[string]string = map[string]string{
	"!And":         "Fn::And",
	"!Base64":      "Fn::Base64",
	"!Cidr":        "Fn::Cidr",
	"!Equals":      "Fn::Equals",
	"!FindInMap":   "Fn::FindInMap",
	"!GetAtt":      "Fn::GetAtt",
	"!GetAZs":      "Fn::GetAZs",
	"!If":          "Fn::If",
	"!ImportValue": "Fn::ImportValue",
	"!Join":        "Fn::Join",
	"!Not":         "Fn::Not",
	"!Or":          "Fn::Or",
	"!Ref":         "Ref",
	"!Split":       "Fn::Split",
	"!Sub":         "Fn::Sub",
	"!Transform":   "Fn::Transform",
}

func decodeIntrinsic(node *yaml.Node, name string) (map[string]interface{}, error) {
	if name == "" {
		name = strings.Replace(node.Tag, "!", "Fn::", 1)
	}
	intrinsic := map[string]interface{}{}
	switch node.Kind {
	case yaml.SequenceNode:
		val, err := decodeSeq(node)
		if err != nil {
			return nil, fmt.Errorf("Failed to decode intrinsic containing sequence: %v", err)
		}
		intrinsic[name] = val
	case yaml.MappingNode:
		val, err := decodeMap(node)
		if err != nil {
			return nil, fmt.Errorf("Failed to decode intrinsic containing map: %v", err)
		}
		intrinsic[name] = val
	default:
		var val interface{}
		if err := node.Decode(&val); err != nil {
			return nil, fmt.Errorf("Failed to decode intrinsic: %v", err)
		}
		// Special case for GetAtt
		if name == "Fn::GetAtt" {
			if valString, ok := val.(string); ok {
				parts := strings.Split(valString, ".")

				// take care to cast this to an []interface{}, or our generic
				// code will have issues.
				arr := make([]interface{}, len(parts))
				for i := range parts {
					arr[i] = parts[i]
				}
				val = arr
			}
		}
		intrinsic[name] = val
	}

	return intrinsic, nil
}

func decodeNode(node *yaml.Node) (interface{}, error) {
	switch node.Tag {
	case "!!seq":
		val, err := decodeSeq(node)
		if err != nil {
			return nil, fmt.Errorf("Failed to decode map val: %v", err)
		}
		return val, nil
	case "!!map":
		val, err := decodeMap(node)
		if err != nil {
			return nil, fmt.Errorf("Failed to decode map val: %v", err)
		}
		return val, nil
	default:
		name, isIntrinsic := intrinsicFns[node.Tag]
		if isIntrinsic {
			val, err := decodeIntrinsic(node, name)
			if err != nil {
				return nil, fmt.Errorf("Failed to decode map val: %v", err)
			}
			return val, nil
		}
		var val interface{}
		if err := node.Decode(&val); err != nil {
			return nil, fmt.Errorf("Failed to decode map val: %v", err)
		}
		return val, nil
	}
}

// An interfacetricks.TopDownInterfaceWalker implementation that resolves
// references.  This is ported from Regula but can probably be improved now that
// we are doing things in Go.
type cfnReferenceResolver struct {
	parameters map[string]interface{}
}

func (*cfnReferenceResolver) WalkArray(arr []interface{}) (interface{}, bool) {
	return arr, true
}

func (resolver *cfnReferenceResolver) WalkObject(obj map[string]interface{}) (interface{}, bool) {
	// For consistency with the original Rego code, return a single reference
	// if possible, an array otherwise.  This is something that we'll likely
	// want to revisit.
	refs := resolver.resolveObject(obj)
	if len(refs) == 1 {
		return refs[0], false
	} else if len(refs) > 1 {
		return refs, false
	} else {
		return obj, true
	}
}

// Resolves references to other resources from the given value.  Returns nil
// if not applicable.
func (resolver *cfnReferenceResolver) resolveObject(obj map[string]interface{}) []interface{} {
	if len(obj) == 1 {
		// Replace references by the ID they reference, or a parameter value.
		if ref, ok := obj["Ref"]; ok {
			if str, ok := ref.(string); ok {
				if paramValue, ok := resolver.parameters[str]; ok {
					return []interface{}{paramValue}
				} else {
					return []interface{}{str}
				}
			}
		}

		// Replace {"Fn::GetAtt": [x, "Arn"]} calls by the ID of the resource
		// they reference.
		if argv, ok := obj["Fn::GetAtt"]; ok {
			if args, ok := argv.([]interface{}); ok {
				if len(args) == 2 && args[1] == "Arn" {
					return []interface{}{args[0]}
				}
			}
		}

		// Find references in template strings, like:
		// * "...${LoggingBucket}..."
		// * "...${LoggingBucket.Arn}..."
		// * "...${AWS::Region}..."
		if argv, ok := obj["Fn::Sub"]; ok {
			if tmpl, ok := argv.(string); ok {
				vars := resolver.resolveTemplateString(tmpl)
				refs := make([]interface{}, len(vars))
				for i := range vars {
					refs[i] = vars[i]
				}
				return refs
			}
		}

		// Find references in template strings where a variable map is
		// provided by the user.
		if argv, ok := obj["Fn::Sub"]; ok {
			if args, ok := argv.([]interface{}); ok && len(args) == 2 {
				if tmpl, ok := args[0].(string); ok {
					if mapping, ok := args[1].(map[string]interface{}); ok {
						vars := resolver.resolveTemplateString(tmpl)
						refs := []interface{}{}
						for _, k := range vars {
							if val, ok := mapping[k]; ok {
								refs = append(refs, val)
							}
						}
						return refs
					}
				}
			}
		}

		// Recursively collect references for joins as they are often nested.
		if argv, ok := obj["Fn::Join"]; ok {
			if args, ok := argv.([]interface{}); ok && len(args) == 2 {
				if parts, ok := args[1].([]interface{}); ok {
					refs := []interface{}{}
					for _, arg := range parts {
						if argObj, ok := arg.(map[string]interface{}); ok {
							refs = append(refs, resolver.resolveObject(argObj)...)
						}
					}
					return refs
				}
			}
		}
	}

	return nil
}

func (resolver *cfnReferenceResolver) resolveTemplateString(tmpl string) []string {
	re := regexp.MustCompile(`\$\{([:\w]+)[.:\w]*\}`)
	matches := re.FindAllStringSubmatch(tmpl, -1)
	vars := make([]string, len(matches))
	for i, match := range matches {
		vars[i] = match[1]
	}
	return vars
}

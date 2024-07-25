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

package hcl_interpreter

import (
	"fmt"
	"regexp"

	"github.com/hashicorp/hcl/v2"
)

// Utility to strip out "[x]" parts from resource IDs.
var resourceIdBracketPattern = regexp.MustCompile(`\[[^[*]+\]`)

func (v *Evaluation) Location(
	resourceId string,
	path []interface{},
) []hcl.Range {
	// If we receive a resourceId such as `aws_s3_bucket.my_bucket[0]`, we want
	// to strip out any `[0]` part, since the source code syntax does not have
	// any concept of these "multi"-resources.
	resourceId = resourceIdBracketPattern.ReplaceAllLiteralString(resourceId, "")

	// Find resource location.
	resource, ok := v.Analysis.Resources[resourceId]
	name, _ := StringToFullName(resourceId)
	if !ok || name == nil {
		return nil
	}
	location := resource.Location

	// Find attribute location, if appropriate.
	if len(path) > 0 {
		resourceNode := &hclSourceNode{
			Object: resource.Body,
			Range:  resource.Location,
		}
		loc, _ := resourceNode.getDescendant(path)
		if loc != nil {
			location = loc.Range
		}
	}

	// Construct stack with modules.
	ranges := []hcl.Range{location}
	for i := len(name.Module); i >= 1; i-- {
		moduleKey := ModuleNameToString(name.Module[:i])
		if module, ok := v.Analysis.Modules[moduleKey]; ok && module.Location != nil {
			ranges = append(ranges, *module.Location)
		}
	}
	return ranges
}

// An `hclSourceNode` represents a syntax tree in the HCL config.
type hclSourceNode struct {
	// Exactly one of the next three fields will be set.
	Object    hcl.Body
	Array     hcl.Blocks
	Attribute *hcl.Attribute

	// This will always be set.
	Range hcl.Range
}

func (node *hclSourceNode) getKey(key string) (*hclSourceNode, error) {
	child := hclSourceNode{}
	if node.Object != nil {
		bodyContent, _, diags := node.Object.PartialContent(&hcl.BodySchema{
			Attributes: []hcl.AttributeSchema{
				{
					Name:     key,
					Required: false,
				},
			},
			Blocks: []hcl.BlockHeaderSchema{
				{
					Type: key,
				},
			},
		})
		if diags.HasErrors() {
			return nil, fmt.Errorf(diags.Error())
		}

		blocks := bodyContent.Blocks.OfType(key)
		if len(blocks) > 0 {
			child.Array = blocks
			child.Range = blocks[0].DefRange
			return &child, nil
		}

		if attribute, ok := bodyContent.Attributes[key]; ok {
			child.Attribute = attribute
			child.Range = attribute.Range
			return &child, nil
		}
	}
	return nil, fmt.Errorf("Expected object")
}

func (node *hclSourceNode) getIndex(index int) (*hclSourceNode, error) {
	child := hclSourceNode{}
	if node.Array != nil {
		if index < 0 || index >= len(node.Array) {
			return nil, fmt.Errorf("hclSourceNode.Get: out of bounds: %d", index)
		}

		child.Object = node.Array[index].Body
		child.Range = node.Array[index].DefRange
		return &child, nil
	}
	return nil, fmt.Errorf("Expected array")
}

func (node *hclSourceNode) getDescendant(path []interface{}) (*hclSourceNode, error) {
	if len(path) == 0 {
		return node, nil
	}

	var child *hclSourceNode
	var err error
	switch k := path[0].(type) {
	case string:
		child, err = node.getKey(k)
	case int:
		child, err = node.getIndex(k)
	case int64:
		child, err = node.getIndex(int(k))
	case float64:
		child, err = node.getIndex(int(k))
	}

	if child == nil {
		return node, err
	}

	return child.getDescendant(path[1:])
}

package hcl_interpreter

import (
	"fmt"

	"github.com/hashicorp/hcl/v2"
)

func (v *Evaluation) Location(
	resourceId string,
	path []interface{},
) []hcl.Range {
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
	case float64:
		child, err = node.getIndex(int(k))
	}

	if child == nil {
		return node, err
	}

	return child.getDescendant(path[1:])
}

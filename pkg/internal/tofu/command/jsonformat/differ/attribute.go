// Copyright (c) The OpenTofu Authors
// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2023 HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package differ

import (
	"github.com/opentofu/opentofu/internal/command/jsonformat/structured"
	"github.com/zclconf/go-cty/cty"
	ctyjson "github.com/zclconf/go-cty/cty/json"

	"github.com/opentofu/opentofu/internal/command/jsonformat/computed"

	"github.com/opentofu/opentofu/internal/command/jsonprovider"
)

func ComputeDiffForAttribute(change structured.Change, attribute *jsonprovider.Attribute) computed.Diff {
	if attribute.AttributeNestedType != nil {
		return computeDiffForNestedAttribute(change, attribute.AttributeNestedType)
	}
	return ComputeDiffForType(change, unmarshalAttribute(attribute))
}

func computeDiffForNestedAttribute(change structured.Change, nested *jsonprovider.NestedType) computed.Diff {
	if sensitive, ok := checkForSensitiveNestedAttribute(change, nested); ok {
		return sensitive
	}

	if computed, ok := checkForUnknownNestedAttribute(change, nested); ok {
		return computed
	}

	switch NestingMode(nested.NestingMode) {
	case nestingModeSingle, nestingModeGroup:
		return computeAttributeDiffAsNestedObject(change, nested.Attributes)
	case nestingModeMap:
		return computeAttributeDiffAsNestedMap(change, nested.Attributes)
	case nestingModeList:
		return computeAttributeDiffAsNestedList(change, nested.Attributes)
	case nestingModeSet:
		return computeAttributeDiffAsNestedSet(change, nested.Attributes)
	default:
		panic("unrecognized nesting mode: " + nested.NestingMode)
	}
}

func ComputeDiffForType(change structured.Change, ctype cty.Type) computed.Diff {
	if sensitive, ok := checkForSensitiveType(change, ctype); ok {
		return sensitive
	}

	if computed, ok := checkForUnknownType(change, ctype); ok {
		return computed
	}

	switch {
	case ctype == cty.NilType, ctype == cty.DynamicPseudoType:
		// Forward nil or dynamic types over to be processed as outputs.
		// There is nothing particularly special about the way outputs are
		// processed that make this unsafe, we could just as easily call this
		// function computeChangeForDynamicValues(), but external callers will
		// only be in this situation when processing outputs so this function
		// is named for their benefit.
		return ComputeDiffForOutput(change)
	case ctype.IsPrimitiveType():
		return computeAttributeDiffAsPrimitive(change, ctype)
	case ctype.IsObjectType():
		return computeAttributeDiffAsObject(change, ctype.AttributeTypes())
	case ctype.IsMapType():
		return computeAttributeDiffAsMap(change, ctype.ElementType())
	case ctype.IsListType():
		return computeAttributeDiffAsList(change, ctype.ElementType())
	case ctype.IsTupleType():
		return computeAttributeDiffAsTuple(change, ctype.TupleElementTypes())
	case ctype.IsSetType():
		return computeAttributeDiffAsSet(change, ctype.ElementType())
	default:
		panic("unrecognized type: " + ctype.FriendlyName())
	}
}

func unmarshalAttribute(attribute *jsonprovider.Attribute) cty.Type {
	ctyType, err := ctyjson.UnmarshalType(attribute.AttributeType)
	if err != nil {
		panic("could not unmarshal attribute type: " + err.Error())
	}
	return ctyType
}

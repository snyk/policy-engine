// Copyright (c) The OpenTofu Authors
// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2023 HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package differ

import (
	"github.com/zclconf/go-cty/cty"

	"github.com/opentofu/opentofu/internal/command/jsonformat/collections"
	"github.com/opentofu/opentofu/internal/command/jsonformat/computed"
	"github.com/opentofu/opentofu/internal/command/jsonformat/computed/renderers"
	"github.com/opentofu/opentofu/internal/command/jsonformat/structured"
)

func computeAttributeDiffAsTuple(change structured.Change, elementTypes []cty.Type) computed.Diff {
	var elements []computed.Diff
	current := change.GetDefaultActionForIteration()
	sliceValue := change.AsSlice()
	for ix, elementType := range elementTypes {
		childValue := sliceValue.GetChild(ix, ix)
		if !childValue.RelevantAttributes.MatchesPartial() {
			// Mark non-relevant attributes as unchanged.
			childValue = childValue.AsNoOp()
		}
		element := ComputeDiffForType(childValue, elementType)
		elements = append(elements, element)
		current = collections.CompareActions(current, element.Action)
	}
	return computed.NewDiff(renderers.List(elements), current, change.ReplacePaths.Matches())
}

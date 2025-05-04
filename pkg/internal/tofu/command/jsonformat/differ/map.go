// Copyright (c) The OpenTofu Authors
// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2023 HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package differ

import (
	"github.com/zclconf/go-cty/cty"

	"github.com/snyk/policy-engine/pkg/internal/tofu/command/jsonformat/collections"
	"github.com/snyk/policy-engine/pkg/internal/tofu/command/jsonformat/computed"
	"github.com/snyk/policy-engine/pkg/internal/tofu/command/jsonformat/computed/renderers"
	"github.com/snyk/policy-engine/pkg/internal/tofu/command/jsonformat/structured"
	"github.com/snyk/policy-engine/pkg/internal/tofu/command/jsonprovider"
	"github.com/snyk/policy-engine/pkg/internal/tofu/plans"
)

func computeAttributeDiffAsMap(change structured.Change, elementType cty.Type) computed.Diff {
	mapValue := change.AsMap()
	elements, current := collections.TransformMap(mapValue.Before, mapValue.After, mapValue.AllKeys(), func(key string) computed.Diff {
		value := mapValue.GetChild(key)
		if !value.RelevantAttributes.MatchesPartial() {
			// Mark non-relevant attributes as unchanged.
			value = value.AsNoOp()
		}
		return ComputeDiffForType(value, elementType)
	})
	return computed.NewDiff(renderers.Map(elements), current, change.ReplacePaths.Matches())
}

func computeAttributeDiffAsNestedMap(change structured.Change, attributes map[string]*jsonprovider.Attribute) computed.Diff {
	mapValue := change.AsMap()
	elements, current := collections.TransformMap(mapValue.Before, mapValue.After, mapValue.ExplicitKeys(), func(key string) computed.Diff {
		value := mapValue.GetChild(key)
		if !value.RelevantAttributes.MatchesPartial() {
			// Mark non-relevant attributes as unchanged.
			value = value.AsNoOp()
		}
		return computeDiffForNestedAttribute(value, &jsonprovider.NestedType{
			Attributes:  attributes,
			NestingMode: "single",
		})
	})
	return computed.NewDiff(renderers.NestedMap(elements), current, change.ReplacePaths.Matches())
}

func computeBlockDiffsAsMap(change structured.Change, block *jsonprovider.Block) (map[string]computed.Diff, plans.Action) {
	mapValue := change.AsMap()
	return collections.TransformMap(mapValue.Before, mapValue.After, mapValue.ExplicitKeys(), func(key string) computed.Diff {
		value := mapValue.GetChild(key)
		if !value.RelevantAttributes.MatchesPartial() {
			// Mark non-relevant attributes as unchanged.
			value = value.AsNoOp()
		}
		return ComputeDiffForBlock(value, block)
	})
}

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
	"github.com/zclconf/go-cty/cty"
)

func NestVal(prefix []string, val cty.Value) cty.Value {
	if len(prefix) == 0 {
		return val
	} else {
		nested := NestVal(prefix[1:], val)
		return cty.ObjectVal(map[string]cty.Value{prefix[0]: nested})
	}
}

// Merges two Values with a preference given to the right object.
func MergeVal(left cty.Value, right cty.Value) cty.Value {
	if left.IsKnown() && left.Type().IsObjectType() && !left.IsNull() &&
		right.IsKnown() && right.Type().IsObjectType() && !right.IsNull() {
		obj := map[string]cty.Value{}
		for k, lv := range left.AsValueMap() {
			obj[k] = lv
		}
		for k, rv := range right.AsValueMap() {
			if lv, ok := obj[k]; ok {
				obj[k] = MergeVal(lv, rv)
			} else {
				obj[k] = rv
			}
		}
		return cty.ObjectVal(obj)
	}

	return right
}

// Look up a given subtree, returns Null if not found
func LookupVal(tree cty.Value, name LocalName) cty.Value {
	for _, k := range name {
		if tree.IsKnown() && tree.Type().IsObjectType() && !tree.IsNull() {
			if tree.Type().HasAttribute(k) {
				tree = tree.GetAttr(k)
			} else {
				return cty.NullVal(cty.EmptyObject)
			}
		} else {
			return cty.NullVal(cty.EmptyObject)
		}
	}

	return tree
}

// Some HCL functions require it to be a map.  Returns an empty map if we
// have anything but an object at the root.
func ValToVariables(tree cty.Value) map[string]cty.Value {
	if tree.IsKnown() && tree.Type().IsObjectType() && !tree.IsNull() {
		return tree.AsValueMap()
	} else {
		return map[string]cty.Value{}
	}
}

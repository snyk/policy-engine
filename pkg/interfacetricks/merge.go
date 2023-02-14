// Copyright 2022-2023 Snyk Ltd
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

package interfacetricks

// Merges two value trees recursively.  If there is a conflict, the right value
// is retained.
func Merge(left interface{}, right interface{}) interface{} {
	return MergeWith(left, right, func(l interface{}, r interface{}) interface{} {
		return r
	})
}

// Like `Merge` but has a more useful return type if you're merging objects.
func MergeObjects(left map[string]interface{}, right map[string]interface{}) map[string]interface{} {
	for k, rv := range right {
		if lv, ok := left[k]; ok {
			Merge(lv, rv)
		} else {
			left[k] = rv
		}
	}
	return left
}

// MergeWith is like Merge but allows you to customize what happens on a
// conflict.
func MergeWith(
	left interface{},
	right interface{},
	conflict func(interface{}, interface{}) interface{},
) interface{} {
	switch l := left.(type) {
	case map[string]interface{}:
		switch r := right.(type) {
		case map[string]interface{}:
			for k, rv := range r {
				if lv, ok := l[k]; ok {
					l[k] = MergeWith(lv, rv, conflict)
				} else {
					l[k] = rv
				}
			}
			return l
		}
	case []interface{}:
		switch r := right.(type) {
		case []interface{}:
			length := len(l)
			if len(r) > length {
				length = len(r)
			}
			arr := make([]interface{}, length)
			for i := 0; i < length; i++ {
				if i < len(l) && i < len(r) {
					arr[i] = MergeWith(l[i], r[i], conflict)
				} else if i < len(l) {
					arr[i] = l[i]
				} else if i < len(r) {
					arr[i] = r[i]
				} else {
					arr[i] = nil
				}
			}
			return arr
		}
	}

	return conflict(left, right)
}

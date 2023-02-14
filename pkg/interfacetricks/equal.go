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

// Recursively test equality of two value trees.
func Equal(left interface{}, right interface{}) bool {
	switch l := left.(type) {
	case []interface{}:
		if r, ok := right.([]interface{}); ok {
			if len(l) != len(r) {
				return false
			}
			for i := range l {
				if !Equal(l[i], r[i]) {
					return false
				}
			}
			return true
		} else {
			return false
		}
	case map[string]interface{}:
		if r, ok := right.(map[string]interface{}); ok {
			if len(l) != len(r) {
				return false
			}
			for k, lv := range l {
				rv, ok := r[k]
				if !ok || !Equal(lv, rv) {
					return false
				}
			}
			return true
		} else {
			return false
		}
	default:
		return left == right
	}
}

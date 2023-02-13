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

// Create a copy of a value, so we can modify it in place.
func Copy(value interface{}) interface{} {
	switch v := value.(type) {
	case map[string]interface{}:
		obj := make(map[string]interface{}, len(v))
		for k, attr := range v {
			obj[k] = Copy(attr)
		}
		return obj
	case []interface{}:
		arr := make([]interface{}, len(v))
		for i, attr := range v {
			arr[i] = Copy(attr)
		}
		return arr
	default:
		return v
	}
}

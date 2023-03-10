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

package interfacetricks

// This is a utility for recursively transforming JSON-like interface values in
// go.
//
// At every step, the transformer returns the new value as well as an indication
// of whether or not we should continue.
type TopDownWalker interface {
	WalkArray([]interface{}) (interface{}, bool)
	WalkObject(map[string]interface{}) (interface{}, bool)

	WalkString(string) (interface{}, bool)
	WalkBool(bool) (interface{}, bool)
}

func TopDownWalk(w TopDownWalker, value interface{}) interface{} {
	switch v := value.(type) {
	case map[string]interface{}:
		updated, cont := w.WalkObject(v)
		if cont {
			return topDownWalkChildren(w, updated)
		} else {
			return updated
		}
	case []interface{}:
		updated, cont := w.WalkArray(v)
		if cont {
			return topDownWalkChildren(w, updated)
		} else {
			return updated
		}
	case string:
		updated, cont := w.WalkString(v)
		if cont {
			return topDownWalkChildren(w, updated)
		} else {
			return updated
		}
	case bool:
		updated, cont := w.WalkBool(v)
		if cont {
			return topDownWalkChildren(w, updated)
		} else {
			return updated
		}
	default:
		return value
	}
}

func topDownWalkChildren(w TopDownWalker, value interface{}) interface{} {
	switch v := value.(type) {
	case map[string]interface{}:
		for k, c := range v {
			v[k] = TopDownWalk(w, c)
		}
		return v
	case []interface{}:
		for i, c := range v {
			v[i] = TopDownWalk(w, c)
		}
		return v
	default:
		return value
	}
}

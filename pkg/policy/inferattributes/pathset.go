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

package inferattributes

import (
	"sort"
)

// pathSet is a trie with either strings or ints as keys.  This allows us
// to represent accessed attributes in a compact way, sharing the prefixes
// for when multiple properties inside a deeply nested structure are
// accessed.  Storing this as a trie also allows us to filter out duplicates
// and overlapping attributes more easily.
type pathSet struct {
	intKeys    map[int]*pathSet
	stringKeys map[string]*pathSet
}

func newPathSet() *pathSet {
	return &pathSet{
		intKeys:    map[int]*pathSet{},
		stringKeys: map[string]*pathSet{},
	}
}

func (ps *pathSet) addInt(k int, path []interface{}) {
	if _, ok := ps.intKeys[k]; !ok {
		ps.intKeys[k] = newPathSet()
	}
	ps.intKeys[k].Add(path)
}

func (ps *pathSet) addString(k string, path []interface{}) {
	if _, ok := ps.stringKeys[k]; !ok {
		ps.stringKeys[k] = newPathSet()
	}
	ps.stringKeys[k].Add(path)
}

func (ps *pathSet) Add(path []interface{}) {
	if len(path) <= 0 {
		return
	}
	switch k := path[0].(type) {
	case int:
		ps.addInt(k, path[1:])
	case float64:
		ps.addInt(int(k), path[1:])
	case string:
		ps.addString(k, path[1:])
	}
}

// List converts the pathSet trie to a list of attributes.
func (ps *pathSet) List() [][]interface{} {
	paths := [][]interface{}{}

	// Sort int keys for consistent ordering
	intKeys := []int{}
	for i := range ps.intKeys {
		intKeys = append(intKeys, i)
	}
	sort.Ints(intKeys)

	// Recursively add children
	for _, k := range intKeys {
		for _, childPath := range ps.intKeys[k].List() {
			path := make([]interface{}, len(childPath)+1)
			path[0] = k
			copy(path[1:], childPath)
			paths = append(paths, path)
		}
	}

	// Sort string keys for consistent ordering
	stringKeys := []string{}
	for i := range ps.stringKeys {
		stringKeys = append(stringKeys, i)
	}
	sort.Strings(stringKeys)

	// Recursively add children
	for _, k := range stringKeys {
		for _, childPath := range ps.stringKeys[k].List() {
			path := make([]interface{}, len(childPath)+1)
			path[0] = k
			copy(path[1:], childPath)
			paths = append(paths, path)
		}
	}

	// Add this node except when we added children
	if len(paths) <= 0 {
		paths = append(paths, []interface{}{})
	}

	return paths
}

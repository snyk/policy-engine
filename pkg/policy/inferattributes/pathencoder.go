// © 2023 Snyk Limited All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package inferattributes

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
)

type pathEncoder struct {
	mutex   sync.RWMutex
	indexes map[string]int
	keys    []string
}

func newPathEncoder() *pathEncoder {
	return &pathEncoder{
		mutex:   sync.RWMutex{},
		indexes: map[string]int{},
		keys:    []string{},
	}
}

func (e *pathEncoder) encodePath(path []interface{}) (string, error) {
	buffer := strings.Builder{}
	for _, elem := range path {
		switch val := elem.(type) {
		case int:
			buffer.WriteString(fmt.Sprintf("d%d", val))
		case float64:
			buffer.WriteString(fmt.Sprintf("d%d", int(val)))
		case string:
			e.mutex.RLock()
			n, ok := e.indexes[val]
			e.mutex.RUnlock()
			if ok {
				buffer.WriteString(fmt.Sprintf("s%d", n))
			} else {
				e.mutex.Lock()
				n := len(e.keys)
				e.keys = append(e.keys, val)
				e.indexes[val] = n
				e.mutex.Unlock()
				buffer.WriteString(fmt.Sprintf("s%d", n))
			}
		default:
			return "", fmt.Errorf("failed to encode path for type %t", elem)
		}
	}
	return buffer.String(), nil
}

func (e *pathEncoder) decodePath(encoded string) ([]interface{}, error) {
	var path []interface{}
	for len(encoded) > 0 {
		c := encoded[0]
		encoded = encoded[1:]
		next := strings.IndexAny(encoded, "ds")
		if next < 0 {
			next = len(encoded)
		}
		d, err := strconv.Atoi(encoded[:next])
		if err != nil {
			return nil, err
		}
		switch c {
		case 'd':
			path = append(path, d)
		case 's':
			if d < 0 || d >= len(e.keys) {
				return nil, fmt.Errorf("unknown interned strings %d", d)
			}
			e.mutex.RLock()
			str := e.keys[d]
			e.mutex.RUnlock()
			path = append(path, str)
		default:
			return nil, fmt.Errorf("unknown path encoding %c", c)
		}

		encoded = encoded[next:]
	}
	return path, nil
}

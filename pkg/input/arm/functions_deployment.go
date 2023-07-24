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

package arm

import "fmt"

func variablesImpl(variables map[string]interface{}) Function {
	return func(args ...interface{}) (interface{}, error) {
		strargs, err := assertAllType[string](args...)
		if err != nil {
			return nil, err
		}
		if len(strargs) != 1 {
			return nil, fmt.Errorf("variables: expected 1 arg, got %d", len(strargs))
		}
		key := strargs[0]
		val, ok := variables[key]
		if !ok {
			return nil, fmt.Errorf("no variable found for key %s", key)
		}
		return val, nil
	}
}

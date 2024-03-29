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

import (
	"fmt"
)

// Some helpers useful to ARM function implementations

func assertAllType[T any](args ...interface{}) ([]T, error) {
	typedArgs := make([]T, len(args))
	for i, arg := range args {
		strarg, ok := arg.(T)
		if !ok {
			return nil, fmt.Errorf("unexpected type for %v", arg)
		}
		typedArgs[i] = strarg
	}
	return typedArgs, nil
}

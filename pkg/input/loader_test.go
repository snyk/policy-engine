// Copyright 2022 Snyk Ltd
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

package input_test

import (
	"fmt"

	"github.com/snyk/policy-engine/pkg/input"
	"github.com/spf13/afero"
)

func ExampleLoader_Load() {
	detector, err := input.DetectorByInputTypes(input.Types{input.Auto})
	if err != nil {
		// ...
	}
	loader := input.NewLoader(detector)
	testInputs := input.Directory{
		Fs:   afero.OsFs{},
		Path: "test_inputs/data",
	}
	walkFunc := func(d input.Detectable, depth int) (skip bool, err error) {
		return loader.Load(d, input.DetectOptions{})
	}
	testInputs.Walk(walkFunc)

	fmt.Println(loader.Count())
	// Output: 7
}

// © 2023 Snyk Limited All rights reserved.
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
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/policy-engine/pkg/input"
	inputs "github.com/snyk/policy-engine/pkg/input/test_inputs"
)

func TestUnparsable(t *testing.T) {
	testInputs := []struct {
		path string
	}{
		{path: "invalid.tf"},
	}
	detector := &input.TfDetector{}

	for _, tc := range testInputs {
		t.Run(tc.path, func(t *testing.T) {
			f := makeMockFile(tc.path, inputs.Contents(t, tc.path))
			config, err := detector.DetectFile(f, input.DetectOptions{})
			assert.Nil(t, config)
			assert.ErrorIs(t, err, input.FailedToParseInput)
		})
	}
}

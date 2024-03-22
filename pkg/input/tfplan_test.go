// © 2022-2023 Snyk Limited All rights reserved.
// Copyright 2021 Fugue, Inc.
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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/policy-engine/pkg/input"
	inputs "github.com/snyk/policy-engine/pkg/input/test_inputs"
)

func TestTfPlanDetector(t *testing.T) {
	testInputs := []struct {
		path     string
		contents []byte
	}{
		{path: "tfplan.json", contents: inputs.Contents(t, "tfplan.0.12.json")},
		{path: "tfplan.json", contents: inputs.Contents(t, "tfplan.0.13.json")},
		{path: "tfplan.json", contents: inputs.Contents(t, "tfplan.0.14.json")},
		{path: "tfplan.json", contents: inputs.Contents(t, "tfplan.0.15.json")},
	}
	detector := &input.TfPlanDetector{}

	for _, i := range testInputs {
		f := makeMockFile(i.path, i.contents)
		loader, err := detector.DetectFile(f, input.DetectOptions{
			IgnoreExt: false,
		})
		assert.Nil(t, err)
		assert.NotNil(t, loader)
		assert.Equal(t, loader.LoadedFiles(), []string{i.path})
	}
}

func TestTfPlanDetectorNotTfContents(t *testing.T) {
	detector := &input.TfPlanDetector{}
	f := makeMockFile("other.json", inputs.Contents(t, "other.json"))
	tfplan, err := detector.DetectFile(f, input.DetectOptions{
		IgnoreExt: false,
	})
	assert.True(t, errors.Is(err, input.InvalidInput))
	assert.Nil(t, tfplan)
}

func TestTfPlanDetectorNotJsonExt(t *testing.T) {
	detector := &input.TfPlanDetector{}
	f := makeMockFile("tfplan.tfplan", inputs.Contents(t, "tfplan.0.15.json"))
	tfplan, err := detector.DetectFile(f, input.DetectOptions{
		IgnoreExt: false,
	})
	assert.True(t, errors.Is(err, input.UnrecognizedFileExtension))
	assert.Nil(t, tfplan)
}

func TestTfPlanDetectorIgnoreExt(t *testing.T) {
	detector := &input.TfPlanDetector{}
	f := makeMockFile("plan.tfplan", inputs.Contents(t, "tfplan.0.15.json"))
	tfplan, err := detector.DetectFile(f, input.DetectOptions{
		IgnoreExt: true,
	})
	assert.Nil(t, err)
	assert.NotNil(t, tfplan)
	assert.Equal(t, tfplan.LoadedFiles(), []string{"plan.tfplan"})
}

func TestTfPlanDetectorNotYAML(t *testing.T) {
	detector := &input.TfPlanDetector{}
	f := makeMockFile("not_tfplan.json", inputs.Contents(t, "text.txt"))
	tfplan, err := detector.DetectFile(f, input.DetectOptions{
		IgnoreExt: false,
	})
	assert.True(t, errors.Is(err, input.FailedToParseInput))
	assert.Nil(t, tfplan)
}

func TestFilterReferences(t *testing.T) {
	type test struct {
		input    []string
		expected []string
	}

	tests := []test{
		{
			input: []string{
				"aws_s3_bucket.bucket.id",
				"aws_s3_bucket.bucket",
			},
			expected: []string{"aws_s3_bucket.bucket"},
		},
		{
			input: []string{
				"aws_s3_bucket.bucket[0].id",
				"aws_s3_bucket.bucket[0]",
				"aws_s3_bucket.bucket",
			},
			expected: []string{"aws_s3_bucket.bucket[0]"},
		},
	}

	for _, test := range tests {
		assert.Equal(t, input.TfPlanFilterReferences(test.input), test.expected)
	}
}

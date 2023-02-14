// Copyright 2022-2023 Snyk Ltd
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

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/policy-engine/pkg/input"
	inputs "github.com/snyk/policy-engine/pkg/input/test_inputs"
)

func makeMockFile(path string, contents []byte) *input.File {
	fsys := afero.NewMemMapFs()
	afero.WriteFile(fsys, path, contents, 0644)
	return &input.File{
		Path: path,
		Fs:   fsys,
	}
}

func TestCfnDetector(t *testing.T) {
	testInputs := []struct {
		path     string
		contents []byte
	}{
		{path: "cfn.yaml", contents: inputs.Contents(t, "cfn.yaml")},
		{path: "cfn.yml", contents: inputs.Contents(t, "cfn.yaml")},
		{path: "cfn.json", contents: inputs.Contents(t, "cfn.json")},
		{path: "cfn_resources.yaml", contents: inputs.Contents(t, "cfn_resources.yaml")},
	}
	detector := &input.CfnDetector{}

	for _, i := range testInputs {
		f := makeMockFile(i.path, i.contents)
		cfn, err := detector.DetectFile(f, input.DetectOptions{
			IgnoreExt: false,
		})
		assert.Nil(t, err)
		assert.NotNil(t, cfn)
		assert.Equal(t, cfn.LoadedFiles(), []string{i.path})
	}
}

func TestCfnDetectorNotCfnContents(t *testing.T) {
	detector := &input.CfnDetector{}
	f := makeMockFile("other.json", inputs.Contents(t, "other.json"))
	cfn, err := detector.DetectFile(f, input.DetectOptions{
		IgnoreExt: false,
	})
	assert.True(t, errors.Is(err, input.InvalidInput))
	assert.Nil(t, cfn)
}

func TestCfnDetectorNotCfnExt(t *testing.T) {
	detector := &input.CfnDetector{}
	f := makeMockFile("cfn.cfn", inputs.Contents(t, "cfn.json"))
	cfn, err := detector.DetectFile(f, input.DetectOptions{
		IgnoreExt: false,
	})
	assert.True(t, errors.Is(err, input.UnrecognizedFileExtension))
	assert.Nil(t, cfn)
}

func TestCfnDetectorIgnoreExt(t *testing.T) {
	detector := &input.CfnDetector{}
	f := makeMockFile("cfn.cfn", inputs.Contents(t, "cfn.json"))
	cfn, err := detector.DetectFile(f, input.DetectOptions{
		IgnoreExt: true,
	})
	assert.Nil(t, err)
	assert.NotNil(t, cfn)
	assert.Equal(t, cfn.LoadedFiles(), []string{"cfn.cfn"})
}

func TestCfnDetectorNotYAML(t *testing.T) {
	detector := &input.CfnDetector{}
	f := makeMockFile("not_cfn.yaml", inputs.Contents(t, "text.txt"))
	cfn, err := detector.DetectFile(f, input.DetectOptions{
		IgnoreExt: false,
	})
	assert.True(t, errors.Is(err, input.FailedToParseInput))
	assert.Nil(t, cfn)
}

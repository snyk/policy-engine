// Copyright 2022 Snyk Ltd
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

package loader_test

import (
	"encoding/json"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/unified-policy-engine/pkg/loader"
	inputs "github.com/snyk/unified-policy-engine/pkg/loader/test_inputs"
	"github.com/snyk/unified-policy-engine/pkg/mocks"
)

func makeMockFile(ctrl *gomock.Controller, path, ext string, contents []byte) loader.InputFile {
	mockFile := mocks.NewMockInputFile(ctrl)
	mockFile.EXPECT().Ext().Return(ext)
	mockFile.EXPECT().Path().Return(path)
	mockFile.EXPECT().Contents().Return(contents, nil)
	return mockFile
}

func TestCfnDetector(t *testing.T) {
	ctrl := gomock.NewController(t)
	testInputs := []struct {
		path     string
		ext      string
		contents []byte
	}{
		{path: "cfn.yaml", ext: ".yaml", contents: inputs.Contents(t, "cfn.yaml")},
		{path: "cfn.yml", ext: ".yml", contents: inputs.Contents(t, "cfn.yaml")},
		{path: "cfn.json", ext: ".yaml", contents: inputs.Contents(t, "cfn.json")},
		{path: "cfn_resources.yaml", ext: ".yaml", contents: inputs.Contents(t, "cfn_resources.yaml")},
	}
	detector := &loader.CfnDetector{}

	for _, i := range testInputs {
		f := makeMockFile(ctrl, i.path, i.ext, i.contents)
		cfn, err := detector.DetectFile(f, loader.DetectOptions{
			IgnoreExt: false,
		})
		assert.Nil(t, err)
		assert.NotNil(t, cfn)
		assert.Equal(t, cfn.LoadedFiles(), []string{i.path})
	}
}

func TestCfnDetectorNotCfnContents(t *testing.T) {
	ctrl := gomock.NewController(t)
	detector := &loader.CfnDetector{}
	f := makeMockFile(ctrl, "other.json", ".json", inputs.Contents(t, "other.json"))
	cfn, err := detector.DetectFile(f, loader.DetectOptions{
		IgnoreExt: false,
	})
	assert.NotNil(t, err)
	assert.Nil(t, cfn)
}

func TestCfnDetectorNotCfnExt(t *testing.T) {
	ctrl := gomock.NewController(t)
	detector := &loader.CfnDetector{}
	f := mocks.NewMockInputFile(ctrl)
	f.EXPECT().Ext().Return(".cfn")
	f.EXPECT().Path().Return("cfn.cfn")
	cfn, err := detector.DetectFile(f, loader.DetectOptions{
		IgnoreExt: false,
	})
	assert.NotNil(t, err)
	assert.Nil(t, cfn)
}

func TestCfnDetectorIgnoreExt(t *testing.T) {
	ctrl := gomock.NewController(t)
	detector := &loader.CfnDetector{}
	f := mocks.NewMockInputFile(ctrl)
	f.EXPECT().Path().Return("cfn.cfn")
	f.EXPECT().Contents().Return(inputs.Contents(t, "cfn.yaml"), nil)
	cfn, err := detector.DetectFile(f, loader.DetectOptions{
		IgnoreExt: true,
	})
	assert.Nil(t, err)
	assert.NotNil(t, cfn)
	assert.Equal(t, cfn.LoadedFiles(), []string{"cfn.cfn"})
}

func TestCfnDetectorNotYAML(t *testing.T) {
	ctrl := gomock.NewController(t)
	detector := &loader.CfnDetector{}
	f := makeMockFile(ctrl, "not_cfn.yaml", ".yaml", inputs.Contents(t, "text.txt"))
	cfn, err := detector.DetectFile(f, loader.DetectOptions{
		IgnoreExt: false,
	})
	assert.NotNil(t, err)
	assert.Nil(t, cfn)
}

func TestCfnYAMLLocation(t *testing.T) {
	ctrl := gomock.NewController(t)
	f := makeMockFile(ctrl, "cfn.yaml", ".yaml", inputs.Contents(t, "cfn.yaml"))
	detector := &loader.CfnDetector{}
	cfn, err := detector.DetectFile(f, loader.DetectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	testInputs := []struct {
		path     []interface{}
		expected loader.LocationStack
	}{
		{
			path: []interface{}{"AWS::S3::Bucket", "Bucket1"},
			expected: loader.LocationStack{loader.Location{
				Path: "cfn.yaml",
				Line: 18,
				Col:  3,
			}},
		},
		{
			path: []interface{}{"AWS::S3::Bucket", "Bucket2"},
			expected: loader.LocationStack{loader.Location{
				Path: "cfn.yaml",
				Line: 22,
				Col:  3,
			}},
		},
	}
	for _, i := range testInputs {
		loc, err := cfn.Location(i.path)
		if err != nil {
			t.Fatal(err)
		}
		assert.Equal(t, i.expected, loc)
	}
}

func TestCfnJSONLocation(t *testing.T) {
	ctrl := gomock.NewController(t)
	f := makeMockFile(ctrl, "cfn.json", ".json", inputs.Contents(t, "cfn.json"))
	detector := &loader.CfnDetector{}
	cfn, err := detector.DetectFile(f, loader.DetectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	testInputs := []struct {
		path     []interface{}
		expected loader.LocationStack
	}{
		{
			path: []interface{}{"AWS::S3::Bucket", "Bucket1"},
			expected: loader.LocationStack{loader.Location{
				Path: "cfn.json",
				Line: 5,
				Col:  9,
			}},
		},
		{
			path: []interface{}{"AWS::S3::Bucket", "Bucket2"},
			expected: loader.LocationStack{loader.Location{
				Path: "cfn.json",
				Line: 11,
				Col:  9,
			}},
		},
	}
	for _, i := range testInputs {
		loc, err := cfn.Location(i.path)
		if err != nil {
			t.Fatal(err)
		}
		assert.Equal(t, i.expected, loc)
	}
}

// This is annoying, but we care about the values (not the types)
func coerceRegulaInput(t *testing.T, regulaInput loader.RegulaInput) loader.RegulaInput {
	coerced := loader.RegulaInput{}
	bytes, err := json.Marshal(regulaInput)
	assert.Nil(t, err)
	err = json.Unmarshal(bytes, &coerced)

	return coerced
}

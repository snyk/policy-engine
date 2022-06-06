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
	"errors"
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
		f := mocks.NewMockInputFile(ctrl)
		f.EXPECT().Ext().Return(i.ext)
		f.EXPECT().Path().Return(i.path)
		f.EXPECT().Contents().Return(i.contents, nil)
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
	assert.True(t, errors.Is(err, loader.InvalidInput))
	assert.Nil(t, cfn)
}

func TestCfnDetectorNotCfnExt(t *testing.T) {
	ctrl := gomock.NewController(t)
	detector := &loader.CfnDetector{}
	f := mocks.NewMockInputFile(ctrl)
	f.EXPECT().Ext().AnyTimes().Return(".cfn")
	cfn, err := detector.DetectFile(f, loader.DetectOptions{
		IgnoreExt: false,
	})
	assert.True(t, errors.Is(err, loader.UnrecognizedFileExtension))
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
	assert.True(t, errors.Is(err, loader.FailedToParseInput))
	assert.Nil(t, cfn)
}

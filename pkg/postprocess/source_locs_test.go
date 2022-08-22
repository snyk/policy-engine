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

package postprocess

import (
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/policy-engine/pkg/input"
	"github.com/snyk/policy-engine/pkg/models"
)

func TestAddResourceToResults01(t *testing.T) {
	filepath := "source_locs_test/template.yaml"

	detector, err := input.DetectorByInputTypes(input.Types{input.Auto})
	assert.Nil(t, err)
	loader := input.NewLoader(detector)
	detectable, err := input.NewDetectable(afero.OsFs{}, filepath)
	assert.Nil(t, err)
	ok, err := loader.Load(detectable, input.DetectOptions{})
	assert.Nil(t, err)
	assert.True(t, ok)

	states := loader.ToStates()
	assert.Len(t, states, 1)
	state := states[0]
	results := &models.Results{
		Results: []models.Result{
			{
				Input: state,
			},
		},
	}

	AddSourceLocs(results, loader)

	assert.Equal(t,
		[]models.SourceLocation{
			{
				Filepath: filepath,
				Line:     16,
				Column:   3,
			},
		},
		results.Results[0].Input.Resources["AWS::S3::Bucket"]["Foo"].Meta["location"],
	)

	assert.Equal(t,
		[]models.SourceLocation{
			{
				Filepath: filepath,
				Line:     20,
				Column:   3,
			},
		},
		results.Results[0].Input.Resources["AWS::S3::Bucket"]["Bar"].Meta["location"],
	)
}

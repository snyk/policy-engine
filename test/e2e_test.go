// © 2022 Snyk Limited All rights reserved.
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

package test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/policy-engine/pkg/bundle"
	"github.com/snyk/policy-engine/pkg/data"
	"github.com/snyk/policy-engine/pkg/engine"
	"github.com/snyk/policy-engine/pkg/input"
	"github.com/snyk/policy-engine/pkg/models"
	"github.com/snyk/policy-engine/pkg/postprocess"
	"github.com/snyk/policy-engine/test/utils"
)

// Utility to write easy golden tests.
func RunEngine(t *testing.T, options *engine.EngineOptions, path string) *models.Results {
	detector, err := input.DetectorByInputTypes(
		input.Types{input.Auto},
	)
	assert.NoError(t, err)
	loader := input.NewLoader(detector)
	fsys := afero.OsFs{}
	detectable, err := input.NewDetectable(fsys, path)
	assert.NoError(t, err)
	_, err = loader.Load(detectable, input.DetectOptions{})
	assert.NoError(t, err)
	ctx := context.Background()
	states := loader.ToStates()
	eng := engine.NewEngine(ctx, options)
	assert.Len(t, eng.InitializationErrors, 0)
	results := eng.Eval(ctx, &engine.EvalOptions{
		Inputs: states,
	})
	postprocess.AddSourceLocs(results, loader)
	return results
}

func TestExamples(t *testing.T) {
	results := RunEngine(
		t,
		&engine.EngineOptions{
			Providers: []data.Provider{
				data.LocalProvider("../examples/metadata/"),
				data.LocalProvider("../examples/"),
			},
		},
		"../examples/main.tf",
	)
	bytes, err := json.MarshalIndent(results, "", "  ")
	assert.NoError(t, err)
	utils.GoldenTest(t, "examples.json", bytes)
}

func TestBundles(t *testing.T) {
	results := RunEngine(
		t,
		&engine.EngineOptions{
			BundleReaders: []bundle.Reader{
				bundle.NewDirReader("../pkg/bundle/v1/test_inputs/complete"),
				bundle.NewDirReader("../pkg/bundle/v1/test_inputs/minimal"),
			},
		},
		"../examples/main.tf",
	)
	assert.Len(t, results.Results, 1)
	bytes, err := json.MarshalIndent(results.Results[0].RuleResults, "", "  ")
	assert.NoError(t, err)
	utils.GoldenTest(t, "bundles.json", bytes)
}

func TestFugueRules(t *testing.T) {
	results := RunEngine(
		t,
		&engine.EngineOptions{
			Providers: []data.Provider{
				data.LocalProvider("fuguerules"),
			},
		},
		"../examples/main.tf",
	)
	assert.Len(t, results.Results, 1)
	bytes, err := json.MarshalIndent(results.Results[0].RuleResults, "", "  ")
	assert.NoError(t, err)
	utils.GoldenTest(t, "fuguerules.json", bytes)
}

func TestSnykRules(t *testing.T) {
	results := RunEngine(
		t,
		&engine.EngineOptions{
			Providers: []data.Provider{
				data.LocalProvider("snykrules"),
			},
		},
		"../examples/main.tf",
	)
	assert.Len(t, results.Results, 1)
	bytes, err := json.MarshalIndent(results.Results[0].RuleResults, "", "  ")
	assert.NoError(t, err)
	utils.GoldenTest(t, "snykrules.json", bytes)
}

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

package test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/policy-engine/pkg/data"
	"github.com/snyk/policy-engine/pkg/engine"
	"github.com/snyk/policy-engine/pkg/input"
	"github.com/snyk/policy-engine/pkg/postprocess"
	"github.com/snyk/policy-engine/test/utils"
)

func TestExamples(t *testing.T) {
	providers := []data.Provider{
		data.PureRegoLibProvider(),
	}
	providers = append(providers, data.LocalProvider("../examples/metadata/"))
	providers = append(providers, data.LocalProvider("../examples/"))
	detector, err := input.DetectorByInputTypes(
		input.Types{input.Auto},
	)
	assert.NoError(t, err)
	loader := input.NewLoader(detector)
	fsys := afero.OsFs{}
	detectable, err := input.NewDetectable(fsys, "../examples/main.tf")
	assert.NoError(t, err)
	_, err = loader.Load(detectable, input.DetectOptions{})
	assert.NoError(t, err)
	ctx := context.Background()
	states := loader.ToStates()
	eng := engine.NewEngine(ctx, &engine.EngineOptions{
		Providers: providers,
	})
	assert.Nil(t, eng.Errors)
	results := eng.Eval(ctx, &engine.EvalOptions{
		Inputs: states,
	})
	postprocess.AddSourceLocs(results, loader)

	bytes, err := json.MarshalIndent(results, "  ", "  ")
	assert.NoError(t, err)
	utils.GoldenTest(t, "examples_test.json", bytes)
}

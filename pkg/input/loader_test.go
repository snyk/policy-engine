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

package input_test

import (
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"

	"github.com/snyk/policy-engine/pkg/input"
)

func TestLoadTestInputs(t *testing.T) {
	detector, err := input.DetectorByInputTypes(input.Types{input.Auto})
	require.NoError(t, err)
	loader := input.NewLoader(detector)
	testInputs := input.Directory{
		Fs:   afero.OsFs{},
		Path: "test_inputs/data",
	}
	walkFunc := func(d input.Detectable, depth int) (bool, error) {
		return loader.Load(d, input.DetectOptions{})
	}
	testInputs.Walk(walkFunc)

	require.Equal(t, 7, loader.Count())
}

func TestLoadInputsOnce(t *testing.T) {
	detector, err := input.DetectorByInputTypes(input.Types{input.Auto})
	require.NoError(t, err)
	loader := input.NewLoader(detector)

	// First load the containing directory.  Since this contains `main.tf`,
	// we will load it as a terraform unit.
	dir := input.Directory{Fs: afero.OsFs{}, Path: "test_inputs/multiple_files"}
	loaded, err := loader.Load(&dir, input.DetectOptions{})
	require.NoError(t, err)
	require.True(t, loaded)
	require.Equal(t, 1, loader.Count())

	// Now load the specific terraform file.  This should be a noop since it's
	// already loaded as part of the above.
	tf := input.File{Fs: afero.OsFs{}, Path: "test_inputs/multiple_files/main.tf"}
	loaded, err = loader.Load(&tf, input.DetectOptions{})
	require.NoError(t, err)
	require.False(t, loaded)
	require.Equal(t, 1, loader.Count())

	// Now load the cloudformation file there as well.  This should succeed.
	cfn := input.File{Fs: afero.OsFs{}, Path: "test_inputs/multiple_files/main.yaml"}
	loaded, err = loader.Load(&cfn, input.DetectOptions{})
	require.NoError(t, err)
	require.True(t, loaded)
	require.Equal(t, 2, loader.Count())
}

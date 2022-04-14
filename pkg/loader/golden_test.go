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

package loader

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/fugue/regula/v2/pkg/git"

	"github.com/stretchr/testify/assert"
)

// Utility for loading IaC directories.
func DefaultParseDirectory(dirPath string) (IACConfiguration, error) {
	name := filepath.Base(dirPath)
	repoFinder := git.NewRepoFinder([]string{})
	directoryOpts := directoryOptions{
		Path:          dirPath,
		Name:          name,
		NoGitIgnore:   false,
		GitRepoFinder: repoFinder,
	}
	dir, err := newDirectory(directoryOpts)
	if err != nil {
		return nil, err
	}

	detectOpts := DetectOptions{
		IgnoreExt:  false,
		IgnoreDirs: false,
	}
	detector, err := DetectorByInputTypes([]InputType{Auto})
	if err != nil {
		return nil, err
	}
	return detector.DetectDirectory(dir, detectOpts)
}

type goldenTest struct {
	directory string
	expected  string
}

func listGoldenTests() ([]goldenTest, error) {
	goldenTests := []goldenTest{}

	matches, err := filepath.Glob("golden_test/*/*")
	if err != nil {
		return nil, err
	}

	for _, match := range matches {
		if filepath.Ext(match) != ".json" {
			goldenTests = append(goldenTests, goldenTest{
				directory: match,
				expected:  match + ".json",
			})
		}
	}

	return goldenTests, nil
}

func TestGolden(t *testing.T) {
	fixTests := false
	for _, arg := range os.Args {
		if arg == "golden-test-fix" {
			fixTests = true
		}
	}

	goldenTests, err := listGoldenTests()
	if err != nil {
		t.Fatal(err)
	}

	for _, entry := range goldenTests {
		t.Run(entry.directory, func(t *testing.T) {
			iac, err := DefaultParseDirectory(entry.directory)
			if err != nil {
				t.Fatal(err)
			}
			if iac == nil {
				t.Fatalf("No configuration found in %s", entry.directory)
			}

			actualBytes, err := json.MarshalIndent(iac.RegulaInput(), "", "  ")
			if err != nil {
				t.Fatal(err)
			}

			expectedBytes := []byte{}
			if _, err := os.Stat(entry.expected); err == nil {
				expectedBytes, _ = ioutil.ReadFile(entry.expected)
				if err != nil {
					t.Fatal(err)
				}
			}

			actual := string(actualBytes)
			expected := string(expectedBytes)
			assert.Equal(t, expected, actual)

			if fixTests {
				ioutil.WriteFile(entry.expected, actualBytes, 0644)
			}
		})
	}
}

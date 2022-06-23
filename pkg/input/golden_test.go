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

package input

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/afero"

	"github.com/stretchr/testify/assert"
)

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

func LoadDirOrContents(t *testing.T, dir Directory, detector Detector) IACConfiguration {
	children, err := dir.Children()
	if err != nil {
		t.Fatal(err)
	}
	if len(children) == 1 {
		iac, err := children[0].DetectType(detector, DetectOptions{})
		if err != nil {
			t.Fatal(err)
		}
		return iac
	}
	iac, err := dir.DetectType(detector, DetectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return iac
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

	detector, err := DetectorByInputTypes(Types{Auto})
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range goldenTests {
		t.Run(entry.directory, func(t *testing.T) {
			iac := LoadDirOrContents(t, Directory{
				Path: entry.directory,
				Fs:   afero.OsFs{},
			}, detector)
			if iac == nil {
				t.Fatalf("No configuration found in %s", entry.directory)
			}

			actualBytes, err := json.MarshalIndent(iac.ToState(), "", "  ")
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

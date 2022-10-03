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

package utils

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

var fixTests bool

func init() {
	for _, arg := range os.Args {
		if arg == "golden-test-fix" {
			fixTests = true
		}
	}
}

func GoldenTest(t *testing.T, expectedPath string, actualBytes []byte) {
	expectedBytes := []byte{}
	if _, err := os.Stat(expectedPath); err == nil {
		expectedBytes, _ = ioutil.ReadFile(expectedPath)
		if err != nil {
			t.Fatal(err)
		}
	}

	actual := string(actualBytes)
	expected := string(expectedBytes)

	if fixTests {
		ioutil.WriteFile(expectedPath, actualBytes, 0644)
	} else {
		assert.Equal(t, expected, actual)
	}
}

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

package arm

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBase64(t *testing.T) {
	res, err := base64Impl("foo")
	require.NoError(t, err)
	require.Equal(t, "Zm9v", res)
}

func TestBase64ToString(t *testing.T) {
	res, err := base64ToStringImpl("Zm9v")
	require.NoError(t, err)
	require.Equal(t, "foo", res)
}

func TestConcat(t *testing.T) {
	res, err := concatImpl("foo", "bar")
	require.NoError(t, err)
	require.Equal(t, "foobar", res)
}

func TestDataURI(t *testing.T) {
	res, err := dataURIImpl("Hello")
	require.NoError(t, err)

	// Behaves slightly differently than the example in https://learn.microsoft.com/en-us/azure/azure-resource-manager/templates/template-functions-string#TestDataURI
	// Note the absence of a hyphen in "data:text/plain;charset=utf8;base64,SGVsbG8="
	// It's not clear whether or not this is a problem, it depends on how tolerant
	// of different representations of charset names Azure is.
	require.Equal(t, "data:text/plain;charset=utf-8;base64,SGVsbG8=", res)
}

func TestDataURIToString(t *testing.T) {
	res, err := dataURIToStringImpl("data:;base64,SGVsbG8sIFdvcmxkIQ==")
	require.NoError(t, err)
	require.Equal(t, "Hello, World!", res)
}

func TestFirst(t *testing.T) {
	res, err := firstImpl("Hello")
	require.NoError(t, err)
	require.Equal(t, "H", res)
}

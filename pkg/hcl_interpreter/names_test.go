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

package hcl_interpreter

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestStringToFullName(t *testing.T) {
	type Test struct {
		input    string
		expected *FullName
	}

	tests := []Test{
		{
			input:    "module.foo.module.bar.aws_s3_bucket.bucket",
			expected: &FullName{ModuleName{"foo", "bar"}, LocalName{"aws_s3_bucket", "bucket"}},
		},
		{
			input:    "local.ports",
			expected: &FullName{ModuleName{}, LocalName{"local", "ports"}},
		},
	}

	for _, test := range tests {
		name, err := StringToFullName(test.input)
		if err != nil {
			t.Fatalf("%s", err)
		}
		assert.Equal(t, test.expected, name)
	}
}

func TestAsModuleInput(t *testing.T) {
	assert.Equal(t,
		&FullName{ModuleName{}, LocalName{"input", "child1", "myvar"}},
		FullName{ModuleName{"child1"}, LocalName{"var", "myvar"}}.AsModuleInput(),
	)
	assert.Nil(t,
		FullName{EmptyModuleName, LocalName{"var", "myvar"}}.AsModuleInput(),
	)
}

func TestAsResourceName(t *testing.T) {
	type Test struct {
		input string
		full  *FullName
		index int
		local LocalName
	}

	tests := []Test{
		{
			input: "aws_s3_bucket.bucket.bucket_prefix",
			full:  &FullName{ModuleName{}, LocalName{"aws_s3_bucket", "bucket"}},
			local: LocalName{"bucket_prefix"},
		},
	}

	for _, test := range tests {
		name, err := StringToFullName(test.input)
		if err != nil {
			t.Fatalf("%s", err)
		}
		full, local := name.AsResourceName()
		assert.Equal(t, test.full, full)
		assert.Equal(t, test.local, local)
	}
}

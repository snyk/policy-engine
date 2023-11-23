package hcl_interpreter

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAccessorToString(t *testing.T) {
	tests := []struct {
		input    accessor
		expected string
	}{
		{
			input:    accessor{"foo", "bar", 3, "qux"},
			expected: "foo.bar[3].qux",
		},
	}
	for i, test := range tests {
		t.Run(fmt.Sprintf("case%02d", i), func(t *testing.T) {
			actual := test.input.toString()
			assert.Equal(t, test.expected, actual)
		})
	}
}

func TestStringToAccessor(t *testing.T) {
	tests := []struct {
		input    string
		expected accessor
		err      bool
	}{
		{
			input:    "foo.bar[3].qux",
			expected: accessor{"foo", "bar", 3, "qux"},
		},
		{
			input:    "[1][2][3]",
			expected: accessor{1, 2, 3},
		},
		{
			input: "foo[3.qux",
			err:   true,
		},
		{
			input: "foo.bar[three].qux",
			err:   true,
		},
	}
	for i, test := range tests {
		t.Run(fmt.Sprintf("case%02d", i), func(t *testing.T) {
			actual, err := stringToAccessor(test.input)
			if test.err {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, test.expected, actual)
			}
		})
	}
}

func TestAccessorToLocalName(t *testing.T) {
	tests := []struct {
		input    accessor
		expected LocalName
		trailing accessor
	}{
		{
			input:    accessor{"aws_s3_bucket", "my_bucket", 0, "id"},
			expected: LocalName{"aws_s3_bucket", "my_bucket"},
			trailing: accessor{0, "id"},
		},
		{
			input:    accessor{},
			expected: LocalName{},
			trailing: accessor{},
		},
		{
			input:    accessor{"aws_s3_bucket", "my_bucket", "id"},
			expected: LocalName{"aws_s3_bucket", "my_bucket", "id"},
			trailing: accessor{},
		},
	}
	for i, test := range tests {
		t.Run(fmt.Sprintf("case%02d", i), func(t *testing.T) {
			actual, trailing := test.input.toLocalName()
			assert.Equal(t, test.expected, actual)
			assert.Equal(t, test.trailing, trailing)
		})
	}
}

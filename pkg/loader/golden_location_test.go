package loader

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

type goldenLocationTest struct {
	directory string
	cases     []goldenLocationTestCase
}

type goldenLocationTestCase struct {
	path     []interface{}
	expected LocationStack
}

var goldenLocationTests = []goldenLocationTest{
	// CFN
	{
		directory: "golden_test/cfn/example-01",
		cases: []goldenLocationTestCase{
			{
				path: []interface{}{"Vpc", "MyVpc"},
				expected: LocationStack{Location{
					Path: "golden_test/cfn/example-01/main.yaml",
					Line: 6,
					Col:  3,
				}},
			},
		},
	},
	{
		directory: "golden_test/cfn/json-01",
		cases: []goldenLocationTestCase{
			{
				path: []interface{}{"AWS::S3::Bucket", "Bucket1"},
				expected: LocationStack{Location{
					Path: "golden_test/cfn/json-01/cfn.json",
					Line: 5,
					Col:  9,
				}},
			},
			{
				path: []interface{}{"AWS::S3::Bucket", "Bucket2"},
				expected: LocationStack{Location{
					Path: "golden_test/cfn/json-01/cfn.json",
					Line: 11,
					Col:  9,
				}},
			},
		},
	},
}

// Tests for attribute locations.  These use the same input files as the
// golden_tests since we have a good amount of coverage there.
func TestGoldenLocation(t *testing.T) {
	for _, test := range goldenLocationTests {
		t.Run(test.directory, func(t *testing.T) {
			iac, err := DefaultParseDirectory(test.directory)
			if err != nil {
				t.Fatal(err)
			}
			if iac == nil {
				t.Fatalf("No configuration found in %s", test.directory)
			}

			for _, cas := range test.cases {
				pathRepr, _ := json.Marshal(cas.path)
				t.Run(string(pathRepr), func(t *testing.T) {
					actual, err := iac.Location(cas.path)
					if err != nil {
						t.Fatal(err)
					}

					assert.Equal(t, cas.expected, actual)
				})
			}
		})
	}
}

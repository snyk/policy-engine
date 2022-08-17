package input

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/spf13/afero"
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
	// ARM
	{
		directory: "golden_test/arm/example-01",
		cases: []goldenLocationTestCase{
			{
				path: []interface{}{
					"golden_test/arm/example-01",
					"Microsoft.Network/virtualNetworks",
					"Microsoft.Network/virtualNetworks/VNet1",
					"properties",
					"addressSpace",
					"addressPrefixes",
					0,
				},
				expected: LocationStack{Location{
					Path: "template.json",
					Line: 13,
					Col:  13,
				}},
			},
			{
				path: []interface{}{
					"golden_test/arm/example-01",
					"Microsoft.Network/virtualNetworks/subnets",
					"Microsoft.Network/virtualNetworks/VNet1/subnets/Subnet1",
					"properties",
					"addressPrefix",
				},
				expected: LocationStack{Location{
					Path: "template.json",
					Line: 30,
					Col:  13,
				}},
			},
			{
				path: []interface{}{
					"golden_test/arm/example-01",
					"Microsoft.Network/virtualNetworks/subnets",
					"Microsoft.Network/virtualNetworks/VNet1/subnets/Subnet2",
					"properties",
					"addressPrefix",
				},
				expected: LocationStack{Location{
					Path: "template.json",
					Line: 43,
					Col:  9,
				}},
			},
			{
				path: []interface{}{
					"golden_test/arm/example-01",
					"Microsoft.Network/virtualNetworks/subnets",
					"Microsoft.Network/virtualNetworks/VNet1/subnets/Subnet2",
				},
				expected: LocationStack{Location{
					Path: "template.json",
					Line: 35,
					Col:  5,
				}},
			},
		},
	},
	// CFN
	{
		directory: "golden_test/cfn/example-01",
		cases: []goldenLocationTestCase{
			{
				path: []interface{}{
					"golden_test/cfn/example-01",
					"Vpc",
					"MyVpc",
				},
				expected: LocationStack{Location{
					Path: "main.yaml",
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
				path: []interface{}{
					"golden_test/cfn/json-01",
					"AWS::S3::Bucket",
					"Bucket1",
				},
				expected: LocationStack{Location{
					Path: "cfn.json",
					Line: 5,
					Col:  9,
				}},
			},
			{
				path: []interface{}{
					"golden_test/cfn/json-01",
					"AWS::S3::Bucket",
					"Bucket2",
				},
				expected: LocationStack{Location{
					Path: "cfn.json",
					Line: 11,
					Col:  9,
				}},
			},
		},
	},
	// Kubernetes
	{
		directory: "golden_test/k8s/example-01",
		cases: []goldenLocationTestCase{
			{
				path: []interface{}{
					"default",
					"Pod",
					"invalid1",
					"spec",
					"containers",
				},
				expected: LocationStack{Location{
					Path: "main.yaml",
					Line: 8,
					Col:  3,
				}},
			},
		},
	},
	// Terraform
	{
		directory: "golden_test/tf/example-terraform-modules",
		cases: []goldenLocationTestCase{
			{
				path: []interface{}{
					"golden_test/tf/example-terraform-modules",
					"aws_security_group",
					"aws_security_group.parent",
				},
				expected: LocationStack{
					{
						Path: "main.tf",
						Line: 22,
						Col:  1,
					},
				},
			},
			{
				path: []interface{}{
					"golden_test/tf/example-terraform-modules",
					"aws_vpc",
					"aws_vpc.parent",
				},
				expected: LocationStack{
					{
						Path: "main.tf",
						Line: 18,
						Col:  1,
					},
				},
			},
			{
				path: []interface{}{
					"golden_test/tf/example-terraform-modules",
					"aws_vpc",
					"module.child1.aws_vpc.child",
				},
				expected: LocationStack{
					{
						Path: filepath.Join("child1", "main.tf"),
						Line: 9,
						Col:  1,
					},
					{
						Path: "main.tf",
						Line: 10,
						Col:  12,
					},
				},
			},
			{
				path: []interface{}{
					"golden_test/tf/example-terraform-modules",
					"aws_security_group",
					"module.child1.module.grandchild1.aws_security_group.grandchild",
				},
				expected: LocationStack{
					{
						Path: filepath.Join("child1", "grandchild1", "main.tf"),
						Line: 9,
						Col:  1,
					},
					{
						Path: filepath.Join("child1", "main.tf"),
						Line: 6,
						Col:  12,
					},
					{
						Path: "main.tf",
						Line: 10,
						Col:  12,
					},
				},
			},
			{
				path: []interface{}{
					"golden_test/tf/example-terraform-modules",
					"aws_vpc",
					"module.child1.module.grandchild1.aws_vpc.grandchild",
				},
				expected: LocationStack{
					{
						Path: filepath.Join("child1", "grandchild1", "main.tf"),
						Line: 5,
						Col:  1,
					},
					{
						Path: filepath.Join("child1", "main.tf"),
						Line: 6,
						Col:  12,
					},
					{
						Path: "main.tf",
						Line: 10,
						Col:  12,
					},
				},
			},
			{
				path: []interface{}{
					"golden_test/tf/example-terraform-modules",
					"aws_security_group",
					"module.child2.aws_security_group.child",
				},
				expected: LocationStack{
					{
						Path: filepath.Join("child2", "main.tf"),
						Line: 9,
						Col:  1,
					},
					{
						Path: "main.tf",
						Line: 14,
						Col:  12,
					},
				},
			},
			{
				path: []interface{}{
					"golden_test/tf/example-terraform-modules",
					"aws_vpc",
					"module.child2.aws_vpc.child",
				},
				expected: []Location{
					{
						Path: filepath.Join("child2", "main.tf"),
						Line: 5,
						Col:  1,
					},
					{
						Path: "main.tf",
						Line: 14,
						Col:  12,
					},
				},
			},
			{
				path: []interface{}{
					"golden_test/tf/example-terraform-modules",
					"aws_vpc",
					"module.child2.aws_vpc.child",
					"cidr_block",
				},
				expected: []Location{
					{
						Path: filepath.Join("child2", "main.tf"),
						Line: 6,
						Col:  3,
					},
					{
						Path: "main.tf",
						Line: 14,
						Col:  12,
					},
				},
			},
		},
	},
	{
		directory: "golden_test/tf/kubernetes-01",
		cases: []goldenLocationTestCase{
			{
				path: []interface{}{
					"main.tf",
					"kubernetes_pod",
					"kubernetes_pod.multiple_containers",
					"spec",
					0,
					"init_container",
					0,
					"env",
				},
				expected: LocationStack{
					{
						Path: "main.tf",
						Line: 13,
						Col:  7,
					},
				},
			},
			{
				path: []interface{}{
					"main.tf",
					"kubernetes_pod",
					"kubernetes_pod.multiple_containers",
					"spec",
					0,
					"container",
					1,
					"security_context",
					0,
					"privileged",
				},
				expected: LocationStack{
					{
						Path: "main.tf",
						Line: 42,
						Col:  9,
					},
				},
			},
		},
	},
}

// Tests for attribute locations.  These use the same input files as the
// golden_tests since we have a good amount of coverage there.
func TestGoldenLocation(t *testing.T) {
	detector, err := DetectorByInputTypes(Types{Auto})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range goldenLocationTests {
		t.Run(test.directory, func(t *testing.T) {
			iac := LoadDirOrContents(t, Directory{
				Path: test.directory,
				Fs:   afero.OsFs{},
			}, detector)
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

					relative := make(LocationStack, len(cas.expected))
					for i := range cas.expected {
						relative[i] = cas.expected[i]
						relative[i].Path = filepath.Join(test.directory, cas.expected[i].Path)
					}
					assert.Equal(t, relative, actual)
				})
			}
		})
	}
}

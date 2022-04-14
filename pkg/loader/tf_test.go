package loader

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTfResourceLocation(t *testing.T) {
	dir := filepath.Join("golden_test", "tf", "example-terraform-modules")
	hcl, err := DefaultParseDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	testInputs := []struct {
		path     []string
		expected LocationStack
	}{
		{
			path: []string{"aws_security_group.parent"},
			expected: LocationStack{
				Location{
					Path: filepath.Join(dir, "main.tf"),
					Line: 22,
					Col:  1,
				},
			},
		},
		{
			path: []string{"aws_vpc.parent"},
			expected: LocationStack{
				Location{
					Path: filepath.Join(dir, "main.tf"),
					Line: 18,
					Col:  1,
				},
			},
		},
		{
			path: []string{"module.child1.aws_vpc.child"},
			expected: LocationStack{
				Location{
					Path: filepath.Join(dir, "child1", "main.tf"),
					Line: 9,
					Col:  1,
				},
				Location{
					Path: filepath.Join(dir, "main.tf"),
					Line: 10,
					Col:  12,
				},
			},
		},
		{
			path: []string{"module.child1.module.grandchild1.aws_security_group.grandchild"},
			expected: LocationStack{
				Location{
					Path: filepath.Join(dir, "child1", "grandchild1", "main.tf"),
					Line: 9,
					Col:  1,
				},
				Location{
					Path: filepath.Join(dir, "child1", "main.tf"),
					Line: 6,
					Col:  12,
				},
				Location{
					Path: filepath.Join(dir, "main.tf"),
					Line: 10,
					Col:  12,
				},
			},
		},
		{
			path: []string{"module.child1.module.grandchild1.aws_vpc.grandchild"},
			expected: LocationStack{
				Location{
					Path: filepath.Join(dir, "child1", "grandchild1", "main.tf"),
					Line: 5,
					Col:  1,
				},
				Location{
					Path: filepath.Join(dir, "child1", "main.tf"),
					Line: 6,
					Col:  12,
				},
				Location{
					Path: filepath.Join(dir, "main.tf"),
					Line: 10,
					Col:  12,
				},
			},
		},
		{
			path: []string{"module.child2.aws_security_group.child"},
			expected: LocationStack{
				Location{
					Path: filepath.Join(dir, "child2", "main.tf"),
					Line: 9,
					Col:  1,
				},
				Location{
					Path: filepath.Join(dir, "main.tf"),
					Line: 14,
					Col:  12,
				},
			},
		},
		{
			path: []string{"module.child2.aws_vpc.child"},
			expected: []Location{
				Location{
					Path: filepath.Join(dir, "child2", "main.tf"),
					Line: 5,
					Col:  1,
				},
				Location{
					Path: filepath.Join(dir, "main.tf"),
					Line: 14,
					Col:  12,
				},
			},
		},
	}
	for _, i := range testInputs {
		loc, err := hcl.Location(i.path)
		if err != nil {
			t.Fatal(err)
		}
		assert.Equal(t, i.expected, loc)
	}
}

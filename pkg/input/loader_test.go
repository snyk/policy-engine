package input_test

import (
	"fmt"

	"github.com/snyk/policy-engine/pkg/input"
	"github.com/spf13/afero"
)

func ExampleLoader_Load() {
	detector, err := input.DetectorByInputTypes(input.Types{input.Auto})
	if err != nil {
		// ...
	}
	loader := input.NewLoader(detector)
	testInputs := input.Directory{
		Fs:   afero.OsFs{},
		Path: "test_inputs/data",
	}
	walkFunc := func(d input.Detectable, depth int) (skip bool, err error) {
		return loader.Load(d, input.DetectOptions{})
	}
	testInputs.Walk(walkFunc)

	fmt.Println(loader.Count())
	// Output: 7
}

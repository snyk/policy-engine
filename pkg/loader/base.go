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
	"fmt"

	"github.com/snyk/unified-policy-engine/pkg/inputs"
	"github.com/snyk/unified-policy-engine/pkg/models"
)

//go:generate mockgen -destination=../mocks/mock_iacconfiguration.go -package=mocks github.com/snyk/unified-policy-engine/pkg/loader IACConfiguration
//go:generate mockgen -destination=../mocks/mock_configurationdetector.go -package=mocks github.com/snyk/unified-policy-engine/pkg/loader ConfigurationDetector
//go:generate mockgen -destination=../mocks/mock_inputpath.go -package=mocks github.com/snyk/unified-policy-engine/pkg/loader InputPath
//go:generate mockgen -destination=../mocks/mock_inputdirectory.go -package=mocks github.com/snyk/unified-policy-engine/pkg/loader InputDirectory
//go:generate mockgen -destination=../mocks/mock_inputfile.go -package=mocks github.com/snyk/unified-policy-engine/pkg/loader InputFile
//go:generate mockgen -destination=../mocks/mock_loadedconfigurations.go -package=mocks github.com/snyk/unified-policy-engine/pkg/loader LoadedConfigurations

// stdIn is the path used for stdin.
const stdIn = "<stdin>"

// Auto is an aggregate type that contains all of the IaC input types that this package
// supports.
var Auto = &inputs.InputType{
	Name: "auto",
	Children: inputs.InputTypes{
		inputs.Arm,
		inputs.CloudFormation,
		inputs.Kubernetes,
		inputs.TerraformHCL,
		inputs.TerraformPlan,
	},
}

// StreamlinedState is a temporary addition until we're able to completely replace the
// old streamlined state format.
var StreamlinedState = &inputs.InputType{
	Name:    "streamlined_state",
	Aliases: []string{"streamlined-state"},
}

// SupportedInputTypes contains all of the input types that this package supports.
var SupportedInputTypes = inputs.InputTypes{
	Auto,
	inputs.Arm,
	inputs.CloudFormation,
	inputs.Kubernetes,
	inputs.TerraformHCL,
	inputs.TerraformPlan,
	StreamlinedState,
}

// LoadedConfigurations is a container for IACConfigurations loaded by Regula.
type LoadedConfigurations interface {
	// AddConfiguration adds a configuration entry for the given path
	AddConfiguration(path string, config IACConfiguration)
	// ConfigurationPath checks if the given path has already been loaded as a
	// part of another IACConfiguration, and if so, returns the path for that
	// configuration.
	ConfigurationPath(path string) *string
	// AlreadyLoaded indicates whether the given path has already been loaded as
	// part of another IACConfiguration.
	AlreadyLoaded(path string) bool
	// Location resolves a file path and attribute path from the regula output to a
	// location within a file.
	//
	// If we are working with a resource-based input, the first element of the
	// attributePath is usually the resource type, and the second one the ID.
	Location(path string, attributePath []interface{}) (LocationStack, error)
	// ToStates converts contained configurations to rule input.
	ToStates() []models.State
	// Count returns the number of loaded configurations.
	Count() int
}

type ConfigurationLoader func() (LoadedConfigurations, error)

// IACConfiguration is a loaded IaC Configuration.
type IACConfiguration interface {
	// ToState() returns the input for the rule engine.
	ToState() models.State
	// LoadedFiles are all of the files contained within this configuration.
	LoadedFiles() []string
	// Location resolves an attribute path to to a file, line and column.
	// If we are working with a resource-based input, the first element of the
	// attributePath is usually the resource type, and the second one the ID.
	Location(attributePath []interface{}) (LocationStack, error)
}

// Location is a filepath, line and column.
type Location struct {
	Path string `json:"path"`
	Line int    `json:"line"`
	Col  int    `json:"column"`
}

// In some cases, we have more than one location, for example:
//
//     attribute "foo" at line 4...
//     included in "rds" module at line 8...
//     included in "main" module at line 3...
//
// These are stored as a call stack, with the most specific location in the
// first position, and the "root of the call stack" at the last position.
type LocationStack = []Location

func (l Location) String() string {
	return fmt.Sprintf("%s:%d:%d", l.Path, l.Line, l.Col)
}

// DetectOptions are options passed to the configuration detectors.
type DetectOptions struct {
	IgnoreExt  bool
	IgnoreDirs bool
}

// ConfigurationDetector implements the visitor part of the visitor pattern for the
// concrete InputPath implementations. A ConfigurationDetector implementation must
// contain functions to visit both directories and files. An empty implementation
// must return nil, nil to indicate that the InputPath has been ignored.
type ConfigurationDetector interface {
	DetectDirectory(i InputDirectory, opts DetectOptions) (IACConfiguration, error)
	DetectFile(i InputFile, opts DetectOptions) (IACConfiguration, error)
}

// InputPath is a generic interface to represent both directories and files that
// can serve as inputs for a ConfigurationDetector.
type InputPath interface {
	DetectType(d ConfigurationDetector, opts DetectOptions) (IACConfiguration, error)
	IsDir() bool
	Path() string
	Name() string
}

// WalkFunc is a callback that's invoked on each descendent of an InputDirectory. It
// returns a boolean that, when true, indicates that i.Walk() should not be called.
type WalkFunc func(i InputPath) (skip bool, err error)

type InputDirectory interface {
	InputPath
	Walk(w WalkFunc) error
	Children() []InputPath
}

type InputFile interface {
	InputPath
	Ext() string
	Contents() ([]byte, error)
}

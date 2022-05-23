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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/sirupsen/logrus"
	"github.com/snyk/unified-policy-engine/pkg/inputs"
	"github.com/snyk/unified-policy-engine/pkg/models"

	"github.com/fugue/regula/v2/pkg/git"
)

// LoadPathsOptions contains options for loading IaC configurations from the given
// set of paths.
type LoadPathsOptions struct {
	// Paths sets which paths the loader will search in for IaC configurations
	Paths []string
	// InputTypes sets which input types the loader will try to parse
	InputTypes inputs.InputTypes
	// NoGitIgnore disables the .gitignore functionality. When true, the loader will
	// not filter the input paths based on the contents of relevant .gitignore files.
	NoGitIgnore bool
	// IgnoreDirs prevents the loader for treating a directory of IaC configurations
	// as a single configuration (e.g. a Terraform module). Instead, each IaC file in
	// the directory will be loaded as a separate configuration.
	IgnoreDirs bool
}

// NoLoadableConfigsError indicates that the loader could not find any recognized
// IaC configurations with the given parameters.
type NoLoadableConfigsError struct {
	paths []string
}

func (e *NoLoadableConfigsError) Error() string {
	return fmt.Sprintf("No loadable files in provided paths: %v", e.paths)
}

// LocalConfigurationLoader returns a ConfigurationLoader that loads IaC configurations
// from local disk.
func LocalConfigurationLoader(options LoadPathsOptions) ConfigurationLoader {
	return func() (LoadedConfigurations, error) {
		configurations := newLoadedConfigurations()
		detector, err := DetectorByInputTypes(options.InputTypes)
		// We want to ignore file extension mismatches when 'auto' is not present in
		// the selected input types and there is only one input type selected.
		autoInputTypeSelected := false
		for _, t := range options.InputTypes {
			if t == Auto {
				autoInputTypeSelected = true
				break
			}
		}
		ignoreFileExtension := !autoInputTypeSelected && len(options.InputTypes) < 2
		if err != nil {
			return nil, err
		}
		walkFunc := func(i InputPath) (skip bool, err error) {
			if configurations.AlreadyLoaded(i.Path()) {
				skip = true
				return
			}
			// Ignore errors when we're recursing
			loader, _ := i.DetectType(detector, DetectOptions{
				IgnoreExt:  false,
				IgnoreDirs: options.IgnoreDirs,
			})
			if loader != nil {
				configurations.AddConfiguration(i.Path(), loader)
			}
			return
		}
		gitRepoFinder := git.NewRepoFinder(options.Paths)
		for _, path := range options.Paths {
			if path == "-" {
				path = stdIn
			} else {
				path = filepath.Clean(path)
			}
			if configurations.AlreadyLoaded(path) {
				continue
			}
			if path == stdIn {
				i := newFile(stdIn, stdIn)
				loader, err := i.DetectType(detector, DetectOptions{
					IgnoreExt: true,
				})
				if err != nil {
					return nil, err
				}
				if loader != nil {
					configurations.AddConfiguration(stdIn, loader)
				} else {
					return nil, fmt.Errorf("Unable to detect input type of stdin")
				}
				continue
			}
			name := filepath.Base(path)
			info, err := os.Stat(path)
			if err != nil {
				return nil, err
			}
			if info.IsDir() {
				// We want to override the gitignore behavior if the user explicitly gives
				// us a directory that is ignored.
				noIgnore := options.NoGitIgnore
				if !noIgnore {
					if repo := gitRepoFinder.FindRepo(path); repo != nil {
						noIgnore = repo.IsPathIgnored(path, true)
					}
				}
				i, err := newDirectory(directoryOptions{
					Path:          path,
					Name:          name,
					NoGitIgnore:   noIgnore,
					GitRepoFinder: gitRepoFinder,
				})
				if err != nil {
					return nil, err
				}
				loader, err := i.DetectType(detector, DetectOptions{
					IgnoreExt:  ignoreFileExtension,
					IgnoreDirs: options.IgnoreDirs,
				})
				if err != nil {
					return nil, err
				}
				if loader != nil {
					configurations.AddConfiguration(path, loader)
				}
				if err := i.Walk(walkFunc); err != nil {
					return nil, err
				}
			} else {
				i := newFile(path, name)
				loader, err := i.DetectType(detector, DetectOptions{
					IgnoreExt: ignoreFileExtension,
				})
				if err != nil {
					return nil, err
				}
				if loader != nil {
					configurations.AddConfiguration(path, loader)
				} else {
					return nil, fmt.Errorf("Unable to detect input type of file %v", i.Path())
				}
			}
		}
		if configurations.Count() < 1 {
			return nil, &NoLoadableConfigsError{options.Paths}
		}

		return configurations, nil
	}
}

type cachedLocation struct {
	LocationStack LocationStack
	Error         error
}

type loadedConfigurations struct {
	configurations map[string]IACConfiguration

	// The corresponding key in configurations for every loaded path.
	//
	// For example, if you have a HCL configuration under "src/vpc", this may
	// contain many paths, such as "src/vpc/.terraform/modules/vpc/main.tf".
	// This map can be used to map those additional paths back to the canonical
	// input path, "src/vpc".
	loadedPaths map[string]string

	locationCache map[string]cachedLocation
}

func newLoadedConfigurations() *loadedConfigurations {
	return &loadedConfigurations{
		configurations: map[string]IACConfiguration{},
		loadedPaths:    map[string]string{},
		locationCache:  map[string]cachedLocation{},
	}
}

func (l *loadedConfigurations) AddConfiguration(path string, config IACConfiguration) {
	l.configurations[path] = config
	l.loadedPaths[path] = path
	for _, f := range config.LoadedFiles() {
		l.loadedPaths[f] = path
		logrus.Debugf("loadedPaths[%s] -> %s", f, path)
	}
}

func (l *loadedConfigurations) ConfigurationPath(path string) *string {
	if fp, ok := l.loadedPaths[path]; ok {
		return &fp
	} else {
		return nil
	}
}

func (l *loadedConfigurations) AlreadyLoaded(path string) bool {
	return l.ConfigurationPath(path) != nil
}

func (l *loadedConfigurations) ToStates() []models.State {
	keys := []string{}
	for k := range l.configurations {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	states := []models.State{}
	for _, k := range keys {
		states = append(states, l.configurations[k].ToState())
	}
	return states
}

func (l *loadedConfigurations) Location(path string, attributePath []interface{}) (LocationStack, error) {
	canonical, ok := l.loadedPaths[path]
	if !ok {
		return nil, fmt.Errorf("Unable to determine location for given path %v and attribute path %v", path, attributePath)
	}

	attribute, err := json.Marshal(attributePath)
	if err != nil {
		return l.configurations[canonical].Location(attributePath)
	}

	key := path + ":" + string(attribute)
	if cached, ok := l.locationCache[key]; ok {
		return cached.LocationStack, cached.Error
	} else {
		location, err := l.configurations[canonical].Location(attributePath)
		l.locationCache[key] = cachedLocation{location, err}
		return location, err
	}
}

func (l *loadedConfigurations) Count() int {
	return len(l.configurations)
}

func detectorByInputType(inputType *inputs.InputType) (ConfigurationDetector, error) {
	switch inputType.Name {
	case Auto.Name:
		return NewAutoDetector(
			&CfnDetector{},
			&TfPlanDetector{},
			&TfDetector{},
			&KubernetesDetector{},
			&ArmDetector{},
		), nil
	case inputs.CloudFormation.Name:
		return &CfnDetector{}, nil
	case inputs.TerraformPlan.Name:
		return &TfPlanDetector{}, nil
	case inputs.TerraformHCL.Name:
		return &TfDetector{}, nil
	case StreamlinedState.Name:
		return &StreamlinedStateDetector{}, nil
	case inputs.Kubernetes.Name:
		return &KubernetesDetector{}, nil
	case inputs.Arm.Name:
		return &ArmDetector{}, nil
	default:
		return nil, fmt.Errorf("Unsupported input type: %v", inputType)
	}
}

func DetectorByInputTypes(inputTypes inputs.InputTypes) (ConfigurationDetector, error) {
	if len(inputTypes) == 0 {
		return detectorByInputType(Auto)
	} else if len(inputTypes) == 1 {
		return detectorByInputType(inputTypes[0])
	}
	inputTypesSet := map[string]bool{}
	for _, i := range inputTypes {
		inputTypesSet[i.Name] = true
	}
	if inputTypesSet[Auto.Name] && !inputTypesSet[StreamlinedState.Name] {
		// Auto includes all other detector types besides streamlined state
		return detectorByInputType(Auto)
	}
	detectors := []ConfigurationDetector{}
	for _, inputType := range inputTypes {
		detector, err := detectorByInputType(inputType)
		if err != nil {
			return nil, err
		}
		detectors = append(detectors, detector)
	}

	return NewAutoDetector(detectors...), nil
}

// Copyright 2022-2023 Snyk Ltd
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

package input

import (
	"fmt"
)

func detectorByInputType(inputType *Type) (Detector, error) {
	switch inputType.Name {
	case Auto.Name:
		return NewMultiDetector(
			&CfnDetector{},
			&TfPlanDetector{},
			&TfDetector{},
			&TfStateDetector{},
			&KubernetesDetector{},
			&ArmDetector{},
		), nil
	case CloudFormation.Name:
		return &CfnDetector{}, nil
	case TerraformPlan.Name:
		return &TfPlanDetector{}, nil
	case TerraformHCL.Name:
		return &TfDetector{}, nil
	case TerraformState.Name:
		return &TfStateDetector{}, nil
	case Kubernetes.Name:
		return &KubernetesDetector{}, nil
	case Arm.Name:
		return &ArmDetector{}, nil
	default:
		return nil, fmt.Errorf("%w: %v", UnsupportedInputType, inputType)
	}
}

// DetectorByInputTypes returns a concrete detector implementation for the given input
// types.
func DetectorByInputTypes(inputTypes Types) (Detector, error) {
	if len(inputTypes) == 0 {
		return detectorByInputType(Auto)
	} else if len(inputTypes) == 1 {
		return detectorByInputType(inputTypes[0])
	}
	inputTypesSet := map[string]bool{}
	for _, i := range inputTypes {
		inputTypesSet[i.Name] = true
	}
	if inputTypesSet[Auto.Name] {
		// Auto includes all other detector types
		return detectorByInputType(Auto)
	}
	detectors := []Detector{}
	for _, inputType := range inputTypes {
		detector, err := detectorByInputType(inputType)
		if err != nil {
			return nil, err
		}
		detectors = append(detectors, detector)
	}

	return NewMultiDetector(detectors...), nil
}

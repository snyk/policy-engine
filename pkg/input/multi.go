// © 2022-2023 Snyk Limited All rights reserved.
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

type MultiDetector struct {
	detectors []Detector
}

func (a *MultiDetector) DetectDirectory(i *Directory, opts DetectOptions) (IACConfiguration, error) {
	for _, d := range a.detectors {
		l, err := i.DetectType(d, opts)
		if err == nil && l != nil {
			return l, nil
		}
	}

	return nil, nil
}

func (a *MultiDetector) DetectFile(i *File, opts DetectOptions) (IACConfiguration, error) {
	for _, d := range a.detectors {
		l, err := i.DetectType(d, opts)
		if err == nil && l != nil {
			return l, nil
		}
	}

	return nil, nil
}

func NewMultiDetector(detectors ...Detector) *MultiDetector {
	return &MultiDetector{
		detectors: detectors,
	}
}

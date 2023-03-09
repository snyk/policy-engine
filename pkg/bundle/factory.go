// © 2023 Snyk Limited All rights reserved.
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

package bundle

import (
	"errors"
	"fmt"
	"strings"

	"github.com/snyk/policy-engine/pkg/bundle/base"
	v1 "github.com/snyk/policy-engine/pkg/bundle/v1"
)

var ErrUnrecognizedBundleFormatVersion = errors.New("unrecognized bundle format version")

func ReadBundle(reader base.Reader) (base.Bundle, error) {
	manifest, err := reader.Manifest()
	if err != nil {
		return nil, err
	}
	producer := &FileProducer{
		Reader: reader,
		Filter: bundleFilter,
	}
	var b base.Bundle
	switch manifest.BundleFormatVersion {
	case v1.VERSION:
		b, err = v1.ReadBundle(producer)
	default:
		return nil, fmt.Errorf("%w: %v", ErrUnrecognizedBundleFormatVersion, manifest.BundleFormatVersion)
	}
	if err != nil {
		return nil, err
	}
	if err := b.Validate(); err != nil {
		return nil, err
	}
	return b, nil
}

func BuildBundle(reader base.Reader, opt ...v1.ManifestOption) (base.Bundle, error) {
	producer := &FileProducer{
		Reader: reader,
		Filter: bundleFilter,
	}
	return v1.BuildBundle(producer, opt...)
}

func bundleFilter(path string) bool {
	if path == "manifest.json" || path == "data.json" {
		return true
	}
	return strings.HasPrefix(path, "rules/") || strings.HasPrefix(path, "lib/")
}

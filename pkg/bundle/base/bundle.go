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

package base

import (
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/snyk/policy-engine/pkg/data"
)

type BundleSource string

type Manifest struct {
	BundleFormatVersion string `json:"bundle_format_version"`
}

type Bundle interface {
	Provider() data.Provider
	BundleFormatVersion() string
	Manifest() interface{}
	SourceInfo() SourceInfo
	Modules() map[string]*ast.Module
	Document() map[string]interface{}
	Validate() error
}

// © 2022-2023 Snyk Limited All rights reserved.
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

package hcl_interpreter

import (
	"errors"
	"strings"

	"github.com/hashicorp/hcl/v2"
)

type SubmoduleLoadingError struct {
	Module string
	Err    error
}

func (err SubmoduleLoadingError) Error() string {
	return "Error loading submodule " + err.Module + ": " + err.Err.Error()
}

type MissingRemoteSubmodulesError struct {
	Dir            string
	MissingModules []string
}

func (err MissingRemoteSubmodulesError) Error() string {
	return "Could not load remote submodules in " + err.Dir + ": " + strings.Join(err.MissingModules, ", ")
}

type EvaluationError struct {
	Diags hcl.Diagnostics
}

func (err EvaluationError) Error() string {
	return "Skipping evaluation: " + err.Diags.Error()
}

type MissingTermError struct {
	Term string
}

func (err MissingTermError) Error() string {
	return "Missing term " + err.Term
}

var errUnhandledValueType = errors.New("Unhandled value type")

var errBadDependencyKey = errors.New("Bad dependency key")

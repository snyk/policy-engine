// Copyright 2022-2023 Snyk Ltd
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
	"path/filepath"
	"sort"

	"github.com/spf13/afero"
)

func findVarFiles(fs afero.Fs, dir string) ([]string, error) {
	// We want to sort files by basename.  The spec is:
	//
	//  -  Environment variables
	//  -  The terraform.tfvars file, if present.
	//  -  The terraform.tfvars.json file, if present.
	//  -  Any *.auto.tfvars or *.auto.tfvars.json files, processed in lexical
	//     order of their filenames.
	//  -  -var and -var-file options on the command line, in the order they are
	//     provided. (This includes variables set by Terraform Cloud workspace.)
	//
	// Source: <https://www.terraform.io/language/values/variables#variable-definition-precedence>
	globs := []string{
		filepath.Join(dir, "terraform.tfvars"),
		filepath.Join(dir, "terraform.tfvars.json"),
		filepath.Join(dir, "*.auto.tfvars"),
		filepath.Join(dir, "*.auto.tfvars.json"),
	}
	matches := []string{}
	for _, glob := range globs {
		m, err := afero.Glob(fs, glob)
		if err != nil {
			return matches, err
		}
		matches = append(sort.StringSlice(matches), m...)
	}
	return matches, nil
}

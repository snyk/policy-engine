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
	"encoding/json"
	"path/filepath"
	"strings"

	"github.com/spf13/afero"
)

////////////////////////////////////////////////////////////////////////////////
// `terraform init` downloads modules and writes a helpful file
// `.terraform/modules/modules.json` that tells us where to find modules
// {"Modules":[{"Key":"","Source":"","Dir":"."},{"Key":"acm","Source":"terraform-aws-modules/acm/aws","Version":"3.0.0","Dir":".terraform/modules/acm"}]}

type TerraformModuleRegister struct {
	data terraformModuleRegisterFile
	dir  string
}

type terraformModuleRegisterFile struct {
	Modules []terraformModuleRegisterEntry `json:"Modules"`
}

type terraformModuleRegisterEntry struct {
	Key    string `json:"Key"`
	Source string `json:"Source"`
	Dir    string `json:"Dir"`
}

func NewTerraformRegister(fsys afero.Fs, dir string) *TerraformModuleRegister {
	registry := TerraformModuleRegister{
		data: terraformModuleRegisterFile{
			[]terraformModuleRegisterEntry{},
		},
		dir: dir,
	}
	path := filepath.Join(dir, ".terraform/modules/modules.json")
	bytes, err := afero.ReadFile(fsys, path)
	if err != nil {
		return &registry
	}
	json.Unmarshal(bytes, &registry.data)
	return &registry
}

func (r *TerraformModuleRegister) GetDir(name ModuleName) *string {
	key := ModuleNameToKey(name)
	for _, entry := range r.data.Modules {
		if entry.Key == key {
			joined := TfFilePathJoin(r.dir, entry.Dir)
			return &joined
		}
	}
	return nil
}

// Takes a module source and returns true if the module is local.
func moduleIsLocal(source string) bool {
	// Relevant bit from terraform docs:
	//    A local path must begin with either ./ or ../ to indicate that a local path
	//    is intended, to distinguish from a module registry address.
	return strings.HasPrefix(source, "./") || strings.HasPrefix(source, "../")
}

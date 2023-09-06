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
	"fmt"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/zclconf/go-cty/cty"
)

// aws_security_group.example.count
// aws_security_group.example
// aws_security_group: { "example" ... }
//
// var.stagename
// module.child1.aws_s3_bucket.bucket
//
//
//
//    aws_security_group.invalid_sg_1.ingress[1].from_port = 22
//    module.child1.some_bucket.bucket_prefix` = "foo"
//    ....
//
//
//

type ModuleName = []string

var EmptyModuleName = []string{}

func ModuleNameToString(moduleName ModuleName) string {
	str := ""
	for _, p := range moduleName {
		if str == "" {
			str += "module."
		} else {
			str += ".module."
		}
		str += p
	}
	return str
}

// ModuleNameToKey produces the internal key used in some parts of terraform
// for modules.  While the user-exposed name (as returned by ModuleNameToString)
// would be something like:
//
//	module.foo.module.lambda
//
// The internal key will be:
//
//	foo.lambda
func ModuleNameToKey(moduleName ModuleName) string {
	return strings.Join(moduleName, ".")
}

func ChildModuleName(moduleName ModuleName, childName string) ModuleName {
	out := make(ModuleName, len(moduleName)+1)
	copy(out, moduleName)
	out[len(moduleName)] = childName
	return out
}

type LocalName []string

var (
    // Supported fixed paths can be checked using Equals.
	PathModuleName         = LocalName{"path", "module"}
	PathRootName           = LocalName{"path", "root"}
	PathCwdName            = LocalName{"path", "cwd"}
	TerraformWorkspaceName = LocalName{"terraform", "workspace"}
)

func LocalNameToString(name LocalName) string {
	return strings.Join(name, ".")
}

func (name LocalName) Equals(other LocalName) bool {
	if len(name) != len(other) {
		return false
	}
	for i := range name {
		if name[i] != other[i] {
			return false
		}
	}
	return true
}

type FullName struct {
	Module ModuleName
	Local  LocalName
}

func EmptyFullName(module ModuleName) FullName {
	return FullName{module, nil}
}

func ProviderConfigName(module ModuleName, providerName string) FullName {
	escaped := strings.ReplaceAll(strings.ReplaceAll(providerName, "_", "__"), ".", "_")
	return FullName{module, []string{"provider", escaped}}
}

func takeModulePrefix(parts []string) (*string, []string) {
	if len(parts) >= 2 {
		if parts[0] == "module" {
			return &parts[1], parts[2:]
		}
	}
	return nil, parts
}

func ArrayToFullName(parts []string) FullName {
	module := ModuleName{}

	m, parts := takeModulePrefix(parts)
	for m != nil {
		module = append(module, *m)
		m, parts = takeModulePrefix(parts)
	}

	return FullName{Module: module, Local: parts}
}

func StringToFullName(name string) (*FullName, error) {
	parts := strings.Split(name, ".")
	full := ArrayToFullName(parts)
	return &full, nil
}

func (name FullName) ToString() string {
	if len(name.Module) == 0 {
		return LocalNameToString(name.Local)
	} else {
		return ModuleNameToString(name.Module) + "." + LocalNameToString(name.Local)
	}
}

func (name FullName) Add(p string) FullName {
	local := make([]string, len(name.Local)+1)
	copy(local, name.Local)
	local[len(name.Local)] = p
	return FullName{name.Module, local}
}

//   module.child1.my_output ->
//   module.child1.outputs.my_output

// Parses the use of an output (e.g. "module.child.x") to the fully expanded
// output name (e.g. module.child.output.x")
func (name FullName) AsModuleOutput() *FullName {
	moduleName, tail := takeModulePrefix(name.Local)
	if moduleName != nil && len(tail) == 1 {
		expandedModule := make([]string, len(name.Module)+1)
		copy(expandedModule, name.Module)
		expandedModule[len(name.Module)] = *moduleName
		local := []string{"output", tail[0]}
		return &FullName{expandedModule, local}
	}
	return nil
}

// Parses "module.child.var.foo" into "input.child.foo"
func (name FullName) AsModuleInput() *FullName {
	if len(name.Module) > 0 && len(name.Local) >= 2 {
		if name.Local[0] == "var" {
			parentModuleName := make(ModuleName, len(name.Module)-1)
			copy(parentModuleName, name.Module)
			local := LocalName{"input", name.Module[len(name.Module)-1]}
			local = append(local, name.Local[1:]...)
			return &FullName{parentModuleName, local}
		}
	}
	return nil
}

// Parses "var.my_var.key" into "variable.my_var", "var.my_var" and "key".
func (name FullName) AsVariable() (*FullName, *FullName, LocalName) {
	if len(name.Local) >= 2 {
		if name.Local[0] == "var" {
			local := make(LocalName, len(name.Local))
			copy(local, name.Local)
			local[0] = "variable"
			return &FullName{name.Module, local[:2]}, &FullName{name.Module, name.Local[:2]}, local[2:]
		}
	}
	return nil, nil, nil
}

func (name FullName) AsResourceName() (*FullName, LocalName) {
	if len(name.Local) >= 2 {
		cut := 2
		if name.Local[0] == "data" && len(name.Local) >= cut+1 {
			cut += 1
		}

		if name.Local[0] == "var" || name.Local[0] == "local" {
			return nil, nil
		}

		return &FullName{name.Module, name.Local[:cut]}, name.Local[cut:]
	}
	return nil, nil
}

// TODO: Refactor to TraversalToName?
func TraversalToLocalName(traversal hcl.Traversal) (LocalName, error) {
	parts := make([]string, 0)

	for _, traverser := range traversal {
		switch t := traverser.(type) {
		case hcl.TraverseRoot:
			parts = append(parts, t.Name)
		case hcl.TraverseAttr:
			parts = append(parts, t.Name)
		case hcl.TraverseIndex:
			val := t.Key
			if val.IsKnown() {
				if val.Type() == cty.Number {
					// The other parts must be trailing accessors.
					return parts, nil
				} else if val.Type() == cty.String {
					parts = append(parts, val.AsString())
				} else {
					return nil, fmt.Errorf("Unsupported type in TraverseIndex: %s", val.Type().GoString())
				}
			} else {
				return nil, fmt.Errorf("Unknown value in TraverseIndex")
			}
		}
	}

	return parts, nil
}

func TraversalToString(traversal hcl.Traversal) string {
	traverserToString := func(traverser hcl.Traverser) string {
		switch t := traverser.(type) {
		case hcl.TraverseRoot:
			return t.Name
		case hcl.TraverseAttr:
			return t.Name
		case hcl.TraverseIndex:
			val := t.Key
			if val.IsKnown() {
				if val.Type() == cty.Number {
					n := val.AsBigFloat()
					if n.IsInt() {
						i, _ := n.Int64()
						return fmt.Sprintf("[%d]", i)
					}
				} else if val.Type() == cty.String {
					return val.AsString()
				}
			}
		}
		return "?"
	}

	parts := make([]string, len(traversal))
	for i := range traversal {
		parts[i] = traverserToString(traversal[i])
	}

	return strings.Join(parts, ".")
}

// Copyright 2022 Snyk Ltd
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

// Implements the `Data` interface.  Doesn't really do anything.
package hcl_interpreter

import (
	"github.com/zclconf/go-cty/cty"

	"github.com/snyk/policy-engine/pkg/internal/terraform/addrs"
	"github.com/snyk/policy-engine/pkg/internal/terraform/tfdiags"
)

type Data struct {
}

type UnsupportedOperationDiag struct {
}

func (d UnsupportedOperationDiag) Severity() tfdiags.Severity {
	return tfdiags.Error
}

func (d UnsupportedOperationDiag) Description() tfdiags.Description {
	return tfdiags.Description{
		Summary: "Unsupported operation",
		Detail:  "This operation cannot currently be performed by policy-engine.",
	}
}

func (d UnsupportedOperationDiag) Source() tfdiags.Source {
	return tfdiags.Source{}
}

func (d UnsupportedOperationDiag) FromExpr() *tfdiags.FromExpr {
	return nil
}

func (d UnsupportedOperationDiag) ExtraInfo() interface{} {
	return nil
}

func (c *Data) StaticValidateReferences(refs []*addrs.Reference, self addrs.Referenceable) tfdiags.Diagnostics {
	return tfdiags.Diagnostics{UnsupportedOperationDiag{}}
}

func (c *Data) GetCountAttr(addrs.CountAttr, tfdiags.SourceRange) (cty.Value, tfdiags.Diagnostics) {
	return cty.UnknownVal(cty.DynamicPseudoType), tfdiags.Diagnostics{UnsupportedOperationDiag{}}
}

func (c *Data) GetForEachAttr(addrs.ForEachAttr, tfdiags.SourceRange) (cty.Value, tfdiags.Diagnostics) {
	return cty.UnknownVal(cty.DynamicPseudoType), tfdiags.Diagnostics{UnsupportedOperationDiag{}}
}

func (c *Data) GetResource(addrs.Resource, tfdiags.SourceRange) (cty.Value, tfdiags.Diagnostics) {
	return cty.UnknownVal(cty.DynamicPseudoType), tfdiags.Diagnostics{UnsupportedOperationDiag{}}
}

func (c *Data) GetLocalValue(addrs.LocalValue, tfdiags.SourceRange) (cty.Value, tfdiags.Diagnostics) {
	return cty.UnknownVal(cty.DynamicPseudoType), tfdiags.Diagnostics{UnsupportedOperationDiag{}}
}

func (c *Data) GetModule(addrs.ModuleCall, tfdiags.SourceRange) (cty.Value, tfdiags.Diagnostics) {
	return cty.UnknownVal(cty.DynamicPseudoType), tfdiags.Diagnostics{UnsupportedOperationDiag{}}
}

func (c *Data) GetPathAttr(attr addrs.PathAttr, diags tfdiags.SourceRange) (cty.Value, tfdiags.Diagnostics) {
	return cty.UnknownVal(cty.DynamicPseudoType), tfdiags.Diagnostics{UnsupportedOperationDiag{}}
}

func (c *Data) GetTerraformAttr(addrs.TerraformAttr, tfdiags.SourceRange) (cty.Value, tfdiags.Diagnostics) {
	return cty.UnknownVal(cty.DynamicPseudoType), tfdiags.Diagnostics{UnsupportedOperationDiag{}}
}

func (c *Data) GetInputVariable(v addrs.InputVariable, s tfdiags.SourceRange) (cty.Value, tfdiags.Diagnostics) {
	return cty.UnknownVal(cty.DynamicPseudoType), tfdiags.Diagnostics{UnsupportedOperationDiag{}}
}

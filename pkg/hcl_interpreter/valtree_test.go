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

package hcl_interpreter

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/zclconf/go-cty/cty"
)

func TestValTree(t *testing.T) {
	vt := SingletonValTree(LocalName{"menu", 1, "name"}, cty.StringVal("pizza"))
	vt = MergeValTree(vt, SingletonValTree(LocalName{"menu", 1, "price"}, cty.NumberIntVal(10)))
	assert.Equal(t,
		cty.ObjectVal(map[string]cty.Value{
			"menu": cty.TupleVal([]cty.Value{
				cty.NullVal(cty.DynamicPseudoType),
				cty.ObjectVal(map[string]cty.Value{
					"name":  cty.StringVal("pizza"),
					"price": cty.NumberIntVal(10),
				}),
			}),
		}),
		ValTreeToValue(vt),
	)

	vt = MergeValTree(vt, SingletonValTree(LocalName{"menu", 0, "name"}, cty.StringVal("cake")))
	assert.Equal(t,
		cty.ObjectVal(map[string]cty.Value{
			"menu": cty.TupleVal([]cty.Value{
				cty.ObjectVal(map[string]cty.Value{
					"name": cty.StringVal("cake"),
				}),
				cty.ObjectVal(map[string]cty.Value{
					"name":  cty.StringVal("pizza"),
					"price": cty.NumberIntVal(10),
				}),
			}),
		}),
		ValTreeToValue(vt),
	)

	assert.Equal(t,
		cty.ObjectVal(map[string]cty.Value{
			"menu": cty.TupleVal([]cty.Value{
				cty.NullVal(cty.DynamicPseudoType),
				cty.ObjectVal(map[string]cty.Value{
					"price": cty.NumberIntVal(10),
				}),
			}),
		}),
		ValTreeToValue(SparseValTree(vt, LocalName{"menu", 1, "price"})),
	)
}

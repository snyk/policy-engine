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

package rego

import (
	"testing"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/stretchr/testify/assert"
)

type Primitives struct {
	Bool    bool    `rego:"bool"`
	Int     int     `rego:"int"`
	Float64 float64 `rego:"float64"`
	String  string  `rego:"string"`
}

func TestBindPrimitives(t *testing.T) {
	var actual Primitives
	assert.NoError(t, Bind(ast.NewObject(
		[2]*ast.Term{ast.StringTerm("bool"), ast.BooleanTerm(true)},
		[2]*ast.Term{ast.StringTerm("int"), ast.FloatNumberTerm(42)},
		[2]*ast.Term{ast.StringTerm("float64"), ast.FloatNumberTerm(3.14)},
		[2]*ast.Term{ast.StringTerm("string"), ast.StringTerm("Hello, world!")},
	), &actual))
	assert.Equal(t,
		Primitives{
			Bool:    true,
			Int:     42,
			String:  "Hello, world!",
			Float64: 3.14,
		},
		actual,
	)
}

func TestBindPrimitivesEmpty(t *testing.T) {
	var actual Primitives
	assert.NoError(t, Bind(ast.NewObject(), &actual))
	assert.Equal(t, Primitives{}, actual)
}

type Collections struct {
	Slice     []Primitives   `rego:"slice"`
	MapString map[string]int `rego:"mapstring"`
	MapInt    map[int]string `rego:"mapint"`
	SetInt    []int          `rego:"setint"`
}

func TestBindCollections(t *testing.T) {
	var actual Collections
	assert.NoError(t, Bind(ast.NewObject(
		[2]*ast.Term{
			ast.StringTerm("slice"),
			ast.ArrayTerm(
				ast.NewTerm(ast.NewObject([2]*ast.Term{ast.StringTerm("string"), ast.StringTerm("one!")})),
				ast.NewTerm(ast.NewObject([2]*ast.Term{ast.StringTerm("string"), ast.StringTerm("two!")})),
			),
		},
		[2]*ast.Term{
			ast.StringTerm("mapstring"),
			ast.NewTerm(ast.NewObject(
				[2]*ast.Term{ast.StringTerm("one"), ast.IntNumberTerm(1)},
				[2]*ast.Term{ast.StringTerm("two"), ast.IntNumberTerm(2)},
			)),
		},
		[2]*ast.Term{
			ast.StringTerm("mapint"),
			ast.NewTerm(ast.NewObject(
				[2]*ast.Term{ast.IntNumberTerm(1), ast.StringTerm("one")},
				[2]*ast.Term{ast.IntNumberTerm(2), ast.StringTerm("two")},
			)),
		},
		[2]*ast.Term{
			ast.StringTerm("setint"),
			ast.NewTerm(ast.NewSet(
				ast.IntNumberTerm(1),
				ast.IntNumberTerm(2),
			)),
		},
	), &actual))
	assert.Equal(t,
		Collections{
			Slice:     []Primitives{{String: "one!"}, {String: "two!"}},
			MapString: map[string]int{"one": 1, "two": 2},
			MapInt:    map[int]string{1: "one", 2: "two"},
			SetInt:    []int{1, 2},
		},
		actual,
	)
}

type Structs struct {
	Value   Primitives  `rego:"value"`
	Pointer *Primitives `rego:"pointer"`
	Empty   *Primitives `rego:"empty"`
	Nil     *Primitives `rego:"nil"`
}

func TestStructs(t *testing.T) {
	var actual Structs
	assert.NoError(t, Bind(ast.NewObject(
		[2]*ast.Term{
			ast.StringTerm("value"),
			ast.NewTerm(ast.NewObject(
				[2]*ast.Term{ast.StringTerm("string"), ast.StringTerm("val?")},
			)),
		},
		[2]*ast.Term{
			ast.StringTerm("pointer"),
			ast.NewTerm(ast.NewObject(
				[2]*ast.Term{ast.StringTerm("string"), ast.StringTerm("ptr?")},
			)),
		},
		[2]*ast.Term{
			ast.StringTerm("empty"),
			ast.NewTerm(ast.NewObject()),
		},
	), &actual))
	assert.Equal(t,
		Structs{
			Value:   Primitives{String: "val?"},
			Pointer: &Primitives{String: "ptr?"},
			Empty:   &Primitives{},
			Nil:     nil,
		},
		actual,
	)
}

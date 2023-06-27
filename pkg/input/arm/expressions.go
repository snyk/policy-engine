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

package arm

import (
	"errors"
	"fmt"
)

type expression interface {
	eval(evalCtx EvaluationContext) (interface{}, error)
}

type stringLiteralExpr string

func (s stringLiteralExpr) eval(evalCtx EvaluationContext) (interface{}, error) {
	return string(s), nil
}

type functionExpr struct {
	name string
	args []expression
}

func (f functionExpr) eval(evalCtx EvaluationContext) (interface{}, error) {
	impl, ok := evalCtx.funcs[f.name]
	if !ok {
		return nil, Error{underlying: fmt.Errorf("unsupported function: %s", f.name), kind: UnsupportedFunction}
	}

	argVals := make([]interface{}, len(f.args))
	for i, arg := range f.args {
		var err error
		argVals[i], err = arg.eval(evalCtx)
		if err != nil {
			return nil, Error{underlying: err, kind: EvalError}
		}
	}
	return impl(argVals...)
}

type propertyExpr struct {
	obj      expression
	property string
}

func (p propertyExpr) eval(evalCtx EvaluationContext) (interface{}, error) {
	obj, err := p.obj.eval(evalCtx)
	if err != nil {
		return nil, err
	}
	objMap, ok := obj.(map[string]interface{})
	if !ok {
		return nil, Error{underlying: errors.New("property access can only occur on objects"), kind: EvalError}
	}

	return objMap[p.property], nil
}

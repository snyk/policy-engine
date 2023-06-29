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
	"strings"
)

// Makes state available to ARM template function evaluation. It contains
// references to implementations of functions, and the other fields exist to
// pass data to certain function impls other than what is already in their args.
type EvaluationContext struct {
	DiscoveredResourceSet map[string]struct{}
	Variables             map[string]interface{}
	Functions             map[string]Function
}

type Function func(e *EvaluationContext, args ...interface{}) (interface{}, error)

func BuiltinFunctions() map[string]Function {
	return map[string]Function{
		"base64":          oneStringArg(base64Impl),
		"base64ToString":  oneStringArg(base64ToStringImpl),
		"concat":          concatImpl,
		"dataUri":         oneStringArg(dataURIImpl),
		"dataUriToString": oneStringArg(dataURIToStringImpl),
		"first":           oneStringArg(firstImpl),
		"resourceGroup":   resourceGroupImpl,
		"resourceId":      resourceIDImpl,
		"variables":       variablesImpl,
	}
}

// Detects whether an ARM string is an expression (enclosed by []), and
// tries to evaluate it if so.
func (e *EvaluationContext) EvaluateTemplateString(input string) (interface{}, error) {
	if !IsTemplateExpression(input) {
		return input, nil
	}

	evaluated, err := e.eval(extractAndEscapeTemplateString(input))
	if err != nil {
		if armErr, ok := err.(Error); ok {
			armErr.expression = input
			err = armErr
		}
	}

	return evaluated, err
}

func IsTemplateExpression(input string) bool {
	return strings.HasPrefix(input, "[") && strings.HasSuffix(input, "]")
}

// https://learn.microsoft.com/en-us/azure/azure-resource-manager/templates/template-expressions#escape-characters
func extractAndEscapeTemplateString(input string) string {
	// Remove brackets
	input = input[1:(len(input) - 1)]
	return strings.ReplaceAll(
		strings.ReplaceAll(
			input, "[[", "[",
		), "]]", "]",
	)
}

func (e *EvaluationContext) eval(input string) (interface{}, error) {
	tokens, err := tokenize(input)
	if err != nil {
		return nil, err
	}
	expr, err := parse(tokens)
	if err != nil {
		return nil, err
	}
	return e.evalExpr(expr)
}

func (e *EvaluationContext) evalExpr(expr expression) (interface{}, error) {
	return expr.eval(e)
}

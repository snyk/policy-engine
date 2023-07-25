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

package arm

// DiscoveryBuiltinFunctions returns the functions available during the
// discovery phase.  Functions that retrieve information about resources will
// not yet be available.
func DiscoveryBuiltinFunctions(
	variables map[string]interface{},
) map[string]Function {
	return map[string]Function{
		"base64":          oneStringArg(base64Impl),
		"base64ToString":  oneStringArg(base64ToStringImpl),
		"concat":          concatImpl,
		"dataUri":         oneStringArg(dataURIImpl),
		"dataUriToString": oneStringArg(dataURIToStringImpl),
		"first":           oneStringArg(firstImpl),
		"resourceGroup":   resourceGroupImpl,
		"variables":       variablesImpl(variables),
	}
}

// AllBuiltinFunctions returns all builtin functions available.  This includes
// DiscoveryBuiltinFunctions().
func AllBuiltinFunctions(
	variables map[string]interface{},
	discoveredResourceSet map[string]struct{},
) map[string]Function {
	funcs := DiscoveryBuiltinFunctions(variables)
	funcs["resourceId"] = resourceIDImpl(discoveredResourceSet)
	return funcs
}

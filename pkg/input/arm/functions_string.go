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
	"encoding/base64"
	"fmt"

	"github.com/vincent-petithory/dataurl"
)

// Functions from https://learn.microsoft.com/en-us/azure/azure-resource-manager/templates/template-functions-string#base64

func oneStringArg(f func(string) (interface{}, error)) Function {
	return func(args ...interface{}) (interface{}, error) {
		strargs, err := assertAllType[string](args...)
		if err != nil {
			return nil, err
		}
		if len(strargs) != 1 {
			return nil, fmt.Errorf("expected 1 arg, got %d", len(strargs))
		}
		return f(strargs[0])
	}
}

func base64Impl(arg string) (interface{}, error) {
	return base64.StdEncoding.EncodeToString([]byte(arg)), nil
}

func base64ToStringImpl(arg string) (interface{}, error) {
	decoded, err := base64.StdEncoding.DecodeString(arg)
	if err != nil {
		return nil, fmt.Errorf("error decoding base64: %w", err)
	}
	return string(decoded), nil
}

// TODO base64ToJson returns an object. We can implement this when we introduce
// object variable support.

// TODO concat can operate on arrays too, we just haven't implemented support
// for this yet.
func concatImpl(args ...interface{}) (interface{}, error) {
	res := ""
	for _, arg := range args {
		argStr, ok := arg.(string)
		if !ok {
			return nil, fmt.Errorf("expected argument %#v to be a string", arg)
		}
		res += argStr
	}
	return res, nil
}

// TODO contains can operate on arrays and objects, and returns a boolean. We
// haven't implemented support for these types yet.

func dataURIImpl(arg string) (interface{}, error) {
	return dataurl.EncodeBytes([]byte(arg)), nil
}

func dataURIToStringImpl(arg string) (interface{}, error) {
	decoded, err := dataurl.DecodeString(arg)
	if err != nil {
		return nil, fmt.Errorf("error decoding dataUri: %w", err)
	}
	return string(decoded.Data), nil
}

// TODO empty returns a boolean, a type we haven't implemented support for yet
// TODO endsWith returns a boolean, a type we haven't implemented support for yet

// TODO first can also operate on arrays, a type we haven't implemented support
// for yet
func firstImpl(arg string) (interface{}, error) {
	return string([]rune(arg)[0]), nil
}

// TODO implement format after adding integer and boolean type support

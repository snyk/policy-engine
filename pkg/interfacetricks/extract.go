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

package interfacetricks

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
)

var SetError = errors.New("cannot set destination (hint: use pointer receiver?)")
var TypeError = errors.New("type error")

type ExtractError struct {
	underlying error
	SrcPath    []interface{}
	SrcType    reflect.Type
	DstType    reflect.Type
}

func (e ExtractError) Unwrap() error {
	return e.underlying
}

func (e ExtractError) Error() string {
	pieces := []string{}
	for _, piece := range e.SrcPath {
		switch v := piece.(type) {
		case int:
			pieces = append(pieces, fmt.Sprintf("%d", v))
		case string:
			pieces = append(pieces, v)
		default:
			pieces = append(pieces, fmt.Sprintf("%v", v))
		}
	}

	src := "nil"
	if e.SrcType != nil {
		src = e.SrcType.String()
	}
	dst := "nil"
	if e.DstType != nil {
		dst = e.DstType.String()
	}

	return fmt.Sprintf(
		"extract type mismatch at %s: could not map source %s to destination %s",
		strings.Join(pieces, "/"),
		src,
		dst,
	)
}

// Extract "deserializes" an interface into a target destination, using the
// "encoding/json" conventions.
//
// No actual serialization happens, which means we can avoid a lot of string
// copies.
//
// The extraction will try to continue even when errors are encountered and
// return detailed error information for each problem.
func Extract(src interface{}, dst interface{}) []error {
	return extract([]interface{}{}, src, reflect.ValueOf(dst))
}

// NOTE: This code is based on pkg/rego/bind.go, and updates may need to go
// there as well.
func extract(path []interface{}, src interface{}, dst reflect.Value) (errs []error) {
	ty := dst.Type()

	makeExtractError := func(err error) ExtractError {
		pcopy := make([]interface{}, len(path))
		copy(pcopy, path)
		return ExtractError{
			underlying: err,
			SrcPath:    pcopy,
			SrcType:    reflect.TypeOf(src),
			DstType:    ty,
		}
	}

	if ty.Kind() == reflect.Pointer {
		return extract(path, src, dst.Elem())
	}

	if !dst.CanSet() {
		return []error{makeExtractError(SetError)}
	}

	switch ty.Kind() {
	case reflect.Struct:
		if srcObject, ok := src.(map[string]interface{}); ok {
			for i := 0; i < ty.NumField(); i++ {
				field := ty.Field(i)
				goFieldVal := dst.Field(i)
				goFieldVal.Set(reflect.Zero(field.Type)) // Set to zero/nil
				if jsonFieldName, ok := getJsonFieldName(field); ok {
					if srcFieldVal, ok := srcObject[jsonFieldName]; ok {
						// Initialize if pointer
						if field.Type.Kind() == reflect.Pointer {
							goFieldVal.Set(reflect.New(field.Type.Elem()))
						}

						path = append(path, jsonFieldName)
						errs = append(errs, extract(path, srcFieldVal, goFieldVal)...)
						path = path[:len(path)-1]
					}
				}
			}
			return
		}
	case reflect.Slice:
		if srcArray, ok := src.([]interface{}); ok {
			dst.Set(reflect.MakeSlice(ty, len(srcArray), len(srcArray)))
			for i := 0; i < len(srcArray); i++ {
				path = append(path, i)
				errs = append(errs, extract(path, srcArray[i], dst.Index(i))...)
				path = path[:len(path)-1]
			}
			return
		}
	case reflect.Map:
		if srcObject, ok := src.(map[string]interface{}); ok {
			dst.Set(reflect.MakeMap(ty))
			for k, v := range srcObject {
				path = append(path, k)
				key := reflect.New(ty.Key())
				keyErrs := extract(path, k, key)
				errs = append(errs, keyErrs...)
				if len(keyErrs) == 0 {
					val := reflect.New(ty.Elem())
					errs = append(errs, extract(path, v, val)...)
					dst.SetMapIndex(key.Elem(), val.Elem())
				}
				path = path[:len(path)-1]
			}
			return
		}
	case reflect.Interface:
		dst.Set(reflect.ValueOf(src))
		return
	case reflect.Bool:
		if boolean, ok := src.(bool); ok {
			dst.SetBool(boolean)
			return
		}
	case reflect.Int:
		if number, ok := src.(int64); ok {
			dst.SetInt(number)
			return
		} else if number, ok := src.(int); ok {
			dst.SetInt(int64(number))
			return
		} else if number, ok := src.(float64); ok {
			dst.SetInt(int64(number))
			return
		}
	case reflect.Float64:
		if number, ok := src.(float64); ok {
			dst.SetFloat(number)
			return
		}
	case reflect.String:
		if str, ok := src.(string); ok {
			dst.SetString(str)
			return
		}
	}

	return []error{makeExtractError(TypeError)}
}

func getJsonFieldName(field reflect.StructField) (string, bool) {
	tag, ok := field.Tag.Lookup("json")
	if !ok {
		return "", false
	}
	pieces := strings.SplitN(tag, ",", 2)
	if len(pieces) >= 1 {
		return pieces[0], true
	}
	return "", false
}

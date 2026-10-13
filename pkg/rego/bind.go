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
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/open-policy-agent/opa/v1/ast"
)

const tag = "rego"

func Bind(src ast.Value, dst interface{}) error {
	return bind(src, reflect.ValueOf(dst))
}

func bind(src ast.Value, dst reflect.Value) error {
	ty := dst.Type()
	switch ty.Kind() {
	case reflect.Pointer:
		return bind(src, dst.Elem())
	case reflect.Struct:
		if srcObject, ok := src.(ast.Object); ok {
			for i := 0; i < ty.NumField(); i++ {
				field := ty.Field(i)
				goFieldVal := dst.Field(i)
				goFieldVal.Set(reflect.Zero(field.Type)) // Set to zero/nil
				regoFieldName, ok := field.Tag.Lookup(tag)
				if ok {
					regoFieldVal := srcObject.Get(ast.StringTerm(regoFieldName))
					if regoFieldVal != nil {
						// Initialize if pointer
						if field.Type.Kind() == reflect.Pointer {
							goFieldVal.Set(reflect.New(field.Type.Elem()))
						}

						if err := bind(regoFieldVal.Value, goFieldVal); err != nil {
							return fmt.Errorf("writing Rego field \"%s\" to Go field \"%s\": %w", regoFieldName, field.Name, err)
						}
					}
				}

			}
			return nil
		}
	case reflect.Slice:
		if srcArray, ok := src.(*ast.Array); ok && dst.CanSet() {
			dst.Set(reflect.MakeSlice(ty, srcArray.Len(), srcArray.Len()))
			for i := 0; i < srcArray.Len(); i++ {
				if err := bind(srcArray.Get(ast.IntNumberTerm(i)).Value, dst.Index(i)); err != nil {
					return fmt.Errorf("writing value at index %d: %w", i, err)
				}
			}
			return nil
		} else if srcSet, ok := src.(ast.Set); ok && dst.CanSet() {
			dst.Set(reflect.MakeSlice(ty, srcSet.Len(), srcSet.Len()))
			i := 0
			// NOTE: ast.Set values iterate in a sorted order by default.
			return srcSet.Iter(func(elem *ast.Term) error {
				if err := bind(elem.Value, dst.Index(i)); err != nil {
					return fmt.Errorf("writing set value at index %d: %w", i, err)
				}
				i += 1
				return nil
			})
		}
	case reflect.Map:
		if srcObject, ok := src.(ast.Object); ok && dst.CanSet() {
			dst.Set(reflect.MakeMap(ty))
			return srcObject.Iter(func(k, v *ast.Term) error {
				key := reflect.New(ty.Key())
				if err := bind(k.Value, key); err != nil {
					return err
				}
				val := reflect.New(ty.Elem())
				if err := bind(v.Value, val); err != nil {
					return err
				}
				dst.SetMapIndex(key.Elem(), val.Elem())
				return nil
			})
		}
	case reflect.Interface:
		json, err := ast.JSON(src)
		if err != nil {
			return fmt.Errorf("writing interface as JSON: %w", err)
		}
		if dst.CanSet() {
			dst.Set(reflect.ValueOf(rewriteJsonNumbers(json)))
			return nil
		}
	case reflect.Bool:
		if boolean, ok := src.(ast.Boolean); ok && dst.CanSet() {
			dst.SetBool(bool(boolean))
			return nil
		}
	case reflect.Int:
		if number, ok := src.(ast.Number); ok {
			if n, ok := number.Int64(); ok && dst.CanSet() {
				dst.SetInt(n)
				return nil
			}
		}
	case reflect.Float64:
		if number, ok := src.(ast.Number); ok {
			if f, ok := number.Float64(); ok && dst.CanSet() {
				dst.SetFloat(f)
				return nil
			}
		}
	case reflect.String:
		if str, ok := src.(ast.String); ok && dst.CanSet() {
			dst.SetString(string(str))
			return nil
		}
	}
	return fmt.Errorf("could not write to type: %s", ty.String())
}

func rewriteJsonNumbers(value interface{}) interface{} {
	switch val := value.(type) {
	case map[string]interface{}:
		for k, v := range val {
			val[k] = rewriteJsonNumbers(v)
		}
		return val
	case []interface{}:
		for i, v := range val {
			val[i] = rewriteJsonNumbers(v)
		}
		return val
	case json.Number:
		if f, err := val.Float64(); err == nil {
			return f
		}
	}
	return value
}

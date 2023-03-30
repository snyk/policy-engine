package regobind

import (
	"fmt"
	"reflect"

	"github.com/open-policy-agent/opa/ast"
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
				regoFieldName, ok := field.Tag.Lookup(tag)
				if ok {
					regoFieldVal := srcObject.Get(ast.StringTerm(regoFieldName))
					if regoFieldVal != nil {
						goFieldVal := dst.Field(i)
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
		}
	case reflect.Interface:
		json, err := ast.JSON(src)
		if err != nil {
			return fmt.Errorf("writing interface as JSON: %w", err)
		}
		if dst.CanSet() {
			dst.Set(reflect.ValueOf(json))
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
	case reflect.String:
		if str, ok := src.(ast.String); ok && dst.CanSet() {
			dst.SetString(string(str))
			return nil
		}
	}
	return fmt.Errorf("could not write to type: %s", ty.String())
}

package regobind

import (
	"fmt"
	"os"
	"reflect"

	"github.com/open-policy-agent/opa/ast"
)

const tag = "rego"

func Bind(src ast.Value, dst interface{}) error {
	return bind(src, reflect.ValueOf(dst))
}

func bind(src ast.Value, dst reflect.Value) error {
	ty := dst.Type()
	if ty.Kind() == reflect.Struct {
		if srcObject, ok := src.(ast.Object); ok {
			for i := 0; i < ty.NumField(); i++ {
				field := ty.Field(i)
				regoFieldName, ok := field.Tag.Lookup(tag)
				if ok {
					fmt.Fprintf(os.Stderr, "binding field %s\n", regoFieldName)
					regoFieldVal := srcObject.Get(ast.StringTerm(regoFieldName))
					goFieldVal := dst.Field(i)
					if err := bind(regoFieldVal.Value, goFieldVal); err != nil {
						return err
					}
				}
			}
		} else {
			return fmt.Errorf("Expected object")
		}
	} else if ty.Kind() == reflect.Pointer {
		return bind(src, dst.Elem())
	} else if ty.Kind() == reflect.Int {
		if number, ok := src.(ast.Number); ok {
			if n, ok := number.Int64(); ok {
				dst.SetInt(n)
			}
		}
	} else if ty.Kind() == reflect.String {
		if str, ok := src.(ast.String); ok {
			dst.SetString(str.String())
		}
	}
	return nil
}

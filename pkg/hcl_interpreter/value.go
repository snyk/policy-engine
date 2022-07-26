// cty.Value utilities
package hcl_interpreter

import (
	"fmt"

	"github.com/zclconf/go-cty/cty"
)

func ValueToInt(val cty.Value) *int {
	if !val.IsKnown() || val.IsNull() {
		return nil
	}

	if val.Type() == cty.Number {
		b := val.AsBigFloat()
		if b.IsInt() {
			i64, _ := b.Int64()
			i := int(i64)
			return &i
		}
	}
	return nil
}

func ValueToString(val cty.Value) *string {
	if !val.IsKnown() || val.IsNull() || val.Type() != cty.String {
		return nil
	}

	str := val.AsString()
	return &str
}

func ValueToInterface(val cty.Value) (interface{}, []error) {
	if !val.IsKnown() || val.IsNull() {
		return nil, nil
	}

	if val.Type() == cty.Bool {
		return val.True(), nil
	} else if val.Type() == cty.Number {
		b := val.AsBigFloat()
		if b.IsInt() {
			i, _ := b.Int64()
			return i, nil
		} else {
			f, _ := b.Float64()
			return f, nil
		}
	} else if val.Type() == cty.String {
		return val.AsString(), nil
	} else if val.Type().IsTupleType() || val.Type().IsSetType() || val.Type().IsListType() {
		array := make([]interface{}, 0)
		var errors []error
		for _, elem := range val.AsValueSlice() {
			arr, errs := ValueToInterface(elem)
			array = append(array, arr)
			errors = append(errors, errs...)
		}
		return array, errors
	} else if val.Type().IsMapType() || val.Type().IsObjectType() {
		object := make(map[string]interface{}, 0)
		var errors []error
		for key, attr := range val.AsValueMap() {
			child, errs := ValueToInterface(attr)
			object[key] = child
			errors = append(errors, errs...)
		}
		return object, nil
	}

	return nil, []error{fmt.Errorf("Unhandled value type: %s", val.Type().GoString())}
}

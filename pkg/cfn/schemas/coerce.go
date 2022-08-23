// Copyright 2022 Snyk Ltd
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

package schemas

import (
	"fmt"
	"strconv"
	"strings"
)

func Coerce(val interface{}, schema *Schema) interface{} {
	if schema == nil {
		return val
	}

	switch v := val.(type) {
	case []interface{}:
		return CoerceArray(v, schema)
	case map[string]interface{}:
		return CoerceObject(v, schema)
	case string:
		switch schema.Type {
		case String:
			return v
		case Boolean:
			return strings.ToLower(v) == "true"
		case Integer:
			if n, err := strconv.Atoi(v); err == nil {
				return n
			}
		case Number:
			if f, err := strconv.ParseFloat(v, 64); err == nil {
				return f
			}
		}
	case int:
		switch schema.Type {
		case String:
			return fmt.Sprintf("%d", v)
		}
	case float64:
		switch schema.Type {
		case String:
			return fmt.Sprintf("%f", v)
		}
	}

	return val
}

func CoerceArray(arr []interface{}, schema *Schema) []interface{} {
	if schema == nil || schema.Type != Array || schema.Items == nil {
		return arr
	}

	coerce := make([]interface{}, len(arr))
	for i, v := range arr {
		coerce[i] = Coerce(v, schema.Items)
	}
	return coerce
}

func CoerceObject(obj map[string]interface{}, schema *Schema) map[string]interface{} {
	if schema == nil || schema.Type != Object {
		return obj
	}

	coerce := map[string]interface{}{}
	for k, v := range obj {
		if s, ok := schema.Properties[k]; ok {
			coerce[k] = Coerce(v, s)
		} else {
			coerce[k] = v
		}
	}
	return coerce
}

package interfacetricks

func IntersectWith(
	left interface{},
	right interface{},
	resolve func(interface{}, interface{}) interface{},
) interface{} {
	switch l := left.(type) {
	case map[string]interface{}:
		switch r := right.(type) {
		case map[string]interface{}:
			obj := map[string]interface{}{}
			for k, rv := range r {
				if lv, ok := l[k]; ok {
					obj[k] = IntersectWith(lv, rv, resolve)
				}
			}
			return obj
		}
	case []interface{}:
		switch r := right.(type) {
		case []interface{}:
			length := len(l)
			if len(r) < length {
				length = len(r)
			}
			arr := make([]interface{}, length)
			for i := 0; i < length; i++ {
				if i < length {
					arr[i] = IntersectWith(l[i], r[i], resolve)
				}
			}
			return arr
		}
	}

	return resolve(left, right)
}

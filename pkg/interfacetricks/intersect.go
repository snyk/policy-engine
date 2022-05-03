package interfacetricks

// Create a new object or array containing only the parts that were in both
// trees.  The values in the new tree are determined by the resolve argument.
func IntersectWith(
	left interface{},
	right interface{},
	resolve func(l interface{}, r interface{}) interface{},
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
			arr := make([]interface{}, len(l))
			for i := 0; i < len(l); i++ {
				if i < len(r) {
					arr[i] = IntersectWith(l[i], r[i], resolve)
				} else {
    				arr[i] = l[i]
				}
			}
			return arr
		}
	}

	return resolve(left, right)
}

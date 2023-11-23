package hcl_interpreter

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/zclconf/go-cty/cty"
)

// accessor represents paths in HCL that can contain both string or int parts,
// e.g. "foo.bar[3].qux".
type accessor []interface{}

func (a accessor) toString() string {
	buf := &strings.Builder{}
	for i, p := range a {
		switch p := p.(type) {
		case int:
			fmt.Fprintf(buf, "[%d]", p)
		case string:
			if i == 0 {
				fmt.Fprintf(buf, "%s", p)
			} else {
				fmt.Fprintf(buf, ".%s", p)
			}
		}
	}
	return buf.String()
}

func stringToAccessor(input string) (accessor, error) {
	parts := []interface{}{}
	for len(input) > 0 {
		if input[0] == '[' {
			end := strings.IndexByte(input, ']')
			if end < 0 {
				return nil, fmt.Errorf("unmatched [")
			}
			num, err := strconv.Atoi(input[1:end])
			if err != nil {
				return nil, err
			}
			parts = append(parts, num)
			input = input[end+1:]
			if len(input) > 0 && input[0] == '.' {
				input = input[1:] // Consume extra '.' after ']'
			}
		} else {
			end := strings.IndexAny(input, ".[")
			if end < 0 {
				parts = append(parts, input)
				input = ""
			} else {
				parts = append(parts, input[:end])
				if input[end] == '.' {
					input = input[end+1:]
				} else {
					input = input[end:]
				}
			}
		}
	}
	return parts, nil
}

func traversalToAccessor(traversal hcl.Traversal) (accessor, error) {
	parts := make(accessor, 0)
	for _, traverser := range traversal {
		switch t := traverser.(type) {
		case hcl.TraverseRoot:
			parts = append(parts, t.Name)
		case hcl.TraverseAttr:
			parts = append(parts, t.Name)
		case hcl.TraverseIndex:
			val := t.Key
			if val.IsKnown() {
				if val.Type() == cty.Number {
					n := val.AsBigFloat()
					if n.IsInt() {
						i, _ := n.Int64()
						parts = append(parts, int(i))
					} else {
						return nil, fmt.Errorf("Non-int number type in TraverseIndex")
					}
				} else if val.Type() == cty.String {
					parts = append(parts, val.AsString())
				} else {
					return nil, fmt.Errorf("Unsupported type in TraverseIndex: %s", val.Type().GoString())
				}
			} else {
				return nil, fmt.Errorf("Unknown value in TraverseIndex")
			}
		}
	}
	return parts, nil
}

// toLocalName tries to convert the accessor to a local name starting from the
// front.  As soon as a non-string part is encountered, we stop and return the
// trailing accessor as well.
func (a accessor) toLocalName() (LocalName, accessor) {
	name := make(LocalName, 0)
	trailing := make(accessor, len(a))
	copy(trailing, a)
	for len(trailing) > 0 {
		if str, ok := trailing[0].(string); ok {
			name = append(name, str)
			trailing = trailing[1:]
		} else {
			break
		}
	}
	return name, trailing
}

package policy

import (
	"testing"
)

func TestUnsafeBuiltins(t *testing.T) {
	deny := map[string]struct{}{
		"http.send": {},
	}
	capabilities := Capabilities()
	for _, builtin := range capabilities.Builtins {
		if _, ok := deny[builtin.Name]; ok {
			t.Fatalf("builtin '%s' is supposed to be disabled", builtin.Name)
		}
	}
}

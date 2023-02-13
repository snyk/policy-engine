// Copyright 2022-2023 Snyk Ltd
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

package inferattributes

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPathSet(t *testing.T) {
	ps := newPathSet()

	ps.Add([]interface{}{"network_rule", "ingress", 0, "from_port"})
	assert.Equal(t,
		[][]interface{}{
			{"network_rule", "ingress", 0, "from_port"},
		},
		ps.List(),
	)

	// Should have no effect since there are more specific entries
	ps.Add([]interface{}{"network_rule", "ingress"})
	assert.Equal(t,
		[][]interface{}{
			{"network_rule", "ingress", 0, "from_port"},
		},
		ps.List(),
	)

	ps.Add([]interface{}{"network_rule", "ingress", 1, "to_port"})
	assert.Equal(t,
		[][]interface{}{
			{"network_rule", "ingress", 0, "from_port"},
			{"network_rule", "ingress", 1, "to_port"},
		},
		ps.List(),
	)
}

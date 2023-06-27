// © 2022-2023 Snyk Limited All rights reserved.
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

package arm

import (
	"testing"

	"github.com/stretchr/testify/require"
)

var evalCtx = NewEvaluationContext(
	map[string]struct{}{
		"Microsoft.ServiceBus/namespaces/a-discovered-namespace": {},
	},
)

func TestResourceIDImpl(t *testing.T) {
	for _, tc := range []struct {
		name           string
		args           []interface{}
		expectedOutput string
	}{
		{
			name:           "when a subscription ID, resource group ID, and a single resource type are supplied",
			args:           []interface{}{"a-subscription-id", "resource-group-id", "Microsoft.ServiceBus/namespaces", "namespace1"},
			expectedOutput: "/subscriptions/a-subscription-id/resourceGroups/resource-group-id/providers/Microsoft.ServiceBus/namespaces/namespace1",
		},
		{
			name:           "when resource group ID and a single resource type are supplied",
			args:           []interface{}{"resource-group-id", "Microsoft.ServiceBus/namespaces", "namespace1"},
			expectedOutput: "/subscriptions/stub-subscription-id/resourceGroups/resource-group-id/providers/Microsoft.ServiceBus/namespaces/namespace1",
		},
		{
			name:           "when only a single resource type is supplied",
			args:           []interface{}{"Microsoft.ServiceBus/namespaces", "namespace1"},
			expectedOutput: "/subscriptions/stub-subscription-id/resourceGroups/stub-resource-group-name/providers/Microsoft.ServiceBus/namespaces/namespace1",
		},
		{
			name:           "when multiple resources are supplied",
			args:           []interface{}{"Microsoft.SQL/servers/databases", "serverName", "databaseName"},
			expectedOutput: "/subscriptions/stub-subscription-id/resourceGroups/stub-resource-group-name/providers/Microsoft.SQL/servers/serverName/databases/databaseName",
		},
		{
			name:           "when the calculated ID contains a discovered resource, it is normalized to that form",
			args:           []interface{}{"Microsoft.ServiceBus/namespaces", "a-discovered-namespace"},
			expectedOutput: "Microsoft.ServiceBus/namespaces/a-discovered-namespace",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output, err := evalCtx.resourceIDImpl(tc.args...)
			require.NoError(t, err)
			require.Equal(t, tc.expectedOutput, output)
		})
	}
}

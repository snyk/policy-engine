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

package policy

import (
	"context"
	"sort"

	"github.com/snyk/policy-engine/pkg/models"
)

type inputResolver struct {
	calledWith map[string]bool
	input      *models.State
}

func newInputResolver(input *models.State) *inputResolver {
	return &inputResolver{
		calledWith: map[string]bool{},
		input:      input,
	}
}

func (r *inputResolver) resolve(ctx context.Context, query ResourcesQuery) (ResourcesResult, error) {
	if !ScopeMatches(query.Scope, r.input.Scope) {
		return ResourcesResult{ScopeFound: false}, nil
	}
	ret := ResourcesResult{ScopeFound: true}
	if resources, ok := r.input.Resources[query.ResourceType]; ok {
		ret.ScopeFound = true
		keys := []string{}
		for k := range resources {
			keys = append(keys, k)
		}
		sort.Strings(keys) // Make sure to return in deterministic order
		for _, k := range keys {
			ret.Resources = append(ret.Resources, resources[k])
		}
	}
	r.calledWith[query.ResourceType] = true
	return ret, nil
}

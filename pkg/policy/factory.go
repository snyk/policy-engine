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
	"fmt"
	"strings"
)

func PolicyFactory(moduleSet ModuleSet) (Policy, error) {
	base, err := NewBasePolicy(moduleSet)
	if err != nil {
		return nil, err
	} else if base == nil {
		return nil, nil
	}
	pkg := base.Package()
	if pkg == "data.rules" || strings.HasPrefix(pkg, "data.schemas.") {
		return &LegacyIaCPolicy{BasePolicy: base}, nil
	}
	if base.resourceType == multipleResourceType {
		switch base.judgementRule.name {
		case "deny":
			return &MultiResourcePolicy{
				BasePolicy:       base,
				processResultSet: processMultiDenyPolicyResult,
			}, nil
		case "policy":
			return &MultiResourcePolicy{
				BasePolicy:       base,
				processResultSet: processFuguePolicyResultSet,
			}, nil
		}
	} else {
		switch base.judgementRule.name {
		case "allow":
			if base.judgementRule.hasKey() {
				return &SingleResourcePolicy{
					BasePolicy:       base,
					processResultSet: processFugueAllowPolicyResult,
				}, nil
			} else {
				return &SingleResourcePolicy{
					BasePolicy:       base,
					processResultSet: processFugueAllowBoolean,
				}, nil
			}

		case "deny":
			if base.judgementRule.hasKey() {
				return &SingleResourcePolicy{
					BasePolicy:           base,
					resultBuilderFactory: NewSingleDenyResultBuilder,
				}, nil
			} else {
				return &SingleResourcePolicy{
					BasePolicy:       base,
					processResultSet: processFugueDenyBoolean,
				}, nil
			}
		}
	}
	return nil, fmt.Errorf("Unrecognized policy type in %s", base.Package())
}

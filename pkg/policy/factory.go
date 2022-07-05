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
					BasePolicy:       base,
					processResultSet: processSingleDenyPolicyResult,
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

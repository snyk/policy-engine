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

package version

import (
	"runtime/debug"
	"strings"

	opaversion "github.com/open-policy-agent/opa/version"
	tfversion "github.com/snyk/policy-engine/pkg/internal/terraform/version"
)

// Default build-time variables.
// These values are overridden via ldflags
var (
	// Version is set to the most recent tag at build time
	Version = "unknown-version"
)

// OPAVersion is the canonical version of OPA that is embedded in policy-engine
var OPAVersion = opaversion.Version

// Terraform holds the embedded version of terraform.
var TerraformVersion = tfversion.Version

type VersionInfo struct {
	// Version is set to the most recent tag at build time
	Version string
	// OPAversion is the canonical version of OPA that is embedded in policy-engine
	OPAVersion string
	// Terraform holds the embedded version of terraform.
	TerraformVersion string
	// Revision is the git commit hash at build time
	Revision string
	// HasChanges reflects whether or not the source tree had changes at build time
	HasChanges bool
}

func GetVersionInfo() VersionInfo {
	v := VersionInfo{
		Version:          Version,
		OPAVersion:       OPAVersion,
		TerraformVersion: TerraformVersion,
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			switch setting.Key {
			case "vcs.revision":
				v.Revision = setting.Value
			case "vcs.modified":
				v.HasChanges = setting.Value == "true"
			}
		}
	}
	return v
}

// Plain version, e.g. "1.2.0" rather than "v1.2.0-dev"
func PlainVersion() string {
	plain := strings.TrimPrefix(Version, "v")
	if idx := strings.Index(plain, "-"); idx >= 0 {
		plain = plain[:idx]
	}
	return plain
}

module github.com/snyk/policy-engine

go 1.16

require (
	github.com/agext/levenshtein v1.2.3
	github.com/apparentlymart/go-cidr v1.1.0
	github.com/apparentlymart/go-dump v0.0.0-20190214190832-042adf3cf4a0 // indirect
	github.com/apparentlymart/go-versions v1.0.1
	github.com/bmatcuk/doublestar v1.3.4
	github.com/bmatcuk/doublestar/v4 v4.0.2
	github.com/coreos/go-systemd v0.0.0-20191104093116-d3cd4ed1dbcf // indirect
	github.com/coreos/pkg v0.0.0-20180928190104-399ea9e2e55f
	github.com/fatih/color v1.13.0 // indirect
	github.com/google/uuid v1.3.0
	github.com/hashicorp/errwrap v1.1.0
	github.com/hashicorp/go-cleanhttp v0.5.2
	github.com/hashicorp/go-hclog v1.2.0
	github.com/hashicorp/go-multierror v1.1.1
	github.com/hashicorp/go-retryablehttp v0.7.1
	github.com/hashicorp/go-uuid v1.0.3
	github.com/hashicorp/go-version v1.5.0
	github.com/hashicorp/hcl/v2 v2.12.0
	github.com/hashicorp/terraform-svchost v0.0.0-20200729002733-f050f53b9734
	github.com/hexops/gotextdiff v1.0.3
	github.com/kr/pretty v0.3.0 // indirect
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/mattn/go-colorable v0.1.12 // indirect
	github.com/mattn/go-runewidth v0.0.13 // indirect
	github.com/mitchellh/go-homedir v1.1.0
	github.com/mitchellh/go-wordwrap v1.0.1 // indirect
	github.com/mitchellh/panicwrap v1.0.0
	github.com/open-policy-agent/opa v0.45.1-0.20221025141544-cdbe363e2136
	github.com/peterh/liner v1.2.2 // indirect
	github.com/rcrowley/go-metrics v0.0.0-20201227073835-cf1acfcdf475 // indirect
	github.com/rs/zerolog v1.26.1
	github.com/sergi/go-diff v1.2.0 // indirect
	github.com/spf13/afero v1.8.2
	github.com/spf13/cobra v1.6.1
	github.com/stretchr/testify v1.8.0
	github.com/zclconf/go-cty v1.10.0
	github.com/zclconf/go-cty-yaml v1.0.2
	golang.org/x/crypto v0.0.0-20220525230936-793ad666bf5e
	golang.org/x/mod v0.6.0-dev.0.20220419223038-86c51ed26bb4
	golang.org/x/net v0.0.0-20220909164309-bea034e7d591
	golang.org/x/oauth2 v0.0.0-20220524215830-622c5d57e401 // indirect
	golang.org/x/text v0.4.0
	gopkg.in/yaml.v3 v3.0.1
)

replace github.com/open-policy-agent/opa v0.44.0 => github.com/jaspervdj/opa v0.40.1-0.20221004153720-e5617946277c

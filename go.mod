module github.com/snyk/policy-engine

go 1.24.0

toolchain go1.24.2

require (
	cloud.google.com/go/kms v1.21.2
	cloud.google.com/go/storage v1.53.0
	github.com/Azure/azure-sdk-for-go v59.2.0+incompatible
	github.com/Azure/go-autorest/autorest v0.11.24
	github.com/ProtonMail/go-crypto v1.2.0
	github.com/agext/levenshtein v1.2.3
	github.com/aliyun/alibaba-cloud-sdk-go v1.61.1501
	github.com/aliyun/aliyun-oss-go-sdk v2.2.9+incompatible
	github.com/aliyun/aliyun-tablestore-go-sdk v4.1.2+incompatible
	github.com/apparentlymart/go-cidr v1.1.0
	github.com/apparentlymart/go-dump v0.0.0-20190214190832-042adf3cf4a0
	github.com/apparentlymart/go-shquot v0.0.1
	github.com/apparentlymart/go-versions v1.0.3
	github.com/armon/circbuf v0.0.0-20190214190532-5111143e8da2
	github.com/aws/aws-sdk-go-v2 v1.23.2
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.14.6
	github.com/aws/aws-sdk-go-v2/service/dynamodb v1.25.5
	github.com/aws/aws-sdk-go-v2/service/kms v1.26.5
	github.com/aws/aws-sdk-go-v2/service/s3 v1.46.0
	github.com/aws/smithy-go v1.17.0
	github.com/bgentry/speakeasy v0.1.0
	github.com/bmatcuk/doublestar/v4 v4.8.1
	github.com/chzyer/readline v1.5.1
	github.com/cli/browser v1.3.0
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc
	github.com/dylanmei/winrmtest v0.0.0-20210303004826-fbc9ae56efb6
	github.com/go-test/deep v1.0.3
	github.com/go-viper/mapstructure/v2 v2.2.1
	github.com/golang/mock v1.6.0
	github.com/google/go-cmp v0.7.0
	github.com/google/go-querystring v1.1.0
	github.com/google/uuid v1.6.0
	github.com/googleapis/gax-go/v2 v2.14.1
	github.com/hashicorp/aws-sdk-go-base/v2 v2.0.0-beta.43
	github.com/hashicorp/consul/api v1.13.0
	github.com/hashicorp/consul/sdk v0.8.0
	github.com/hashicorp/errwrap v1.1.0
	github.com/hashicorp/go-azure-helpers v0.43.0
	github.com/hashicorp/go-cleanhttp v0.5.2
	github.com/hashicorp/go-getter v1.7.8
	github.com/hashicorp/go-hclog v1.6.3
	github.com/hashicorp/go-multierror v1.1.1
	github.com/hashicorp/go-plugin v1.4.3
	github.com/hashicorp/go-retryablehttp v0.7.7
	github.com/hashicorp/go-tfe v1.36.0
	github.com/hashicorp/go-uuid v1.0.3
	github.com/hashicorp/go-version v1.7.0
	github.com/hashicorp/hcl v1.0.0
	github.com/hashicorp/hcl/v2 v2.20.1
	github.com/hashicorp/jsonapi v0.0.0-20210826224640-ee7dae0fb22d
	github.com/hashicorp/terraform-svchost v0.1.1
	github.com/hexops/gotextdiff v1.0.3
	github.com/jmespath/go-jmespath v0.4.0
	github.com/kardianos/osext v0.0.0-20190222173326-2bc1f35cddc0
	github.com/lib/pq v1.10.3
	github.com/manicminer/hamilton v0.44.0
	github.com/masterzen/winrm v0.0.0-20200615185753-c42b5136ff88
	github.com/mattn/go-isatty v0.0.20
	github.com/mitchellh/cli v1.1.5
	github.com/mitchellh/colorstring v0.0.0-20190213212951-d06e56a500db
	github.com/mitchellh/copystructure v1.2.0
	github.com/mitchellh/go-homedir v1.1.0
	github.com/mitchellh/go-linereader v0.0.0-20190213213312-1b945b3263eb
	github.com/mitchellh/go-wordwrap v1.0.1
	github.com/mitchellh/reflectwalk v1.0.2
	github.com/open-policy-agent/opa v1.4.2
	github.com/openbao/openbao/api v0.0.0-20240326035453-c075f0ef2c7e
	github.com/opentofu/registry-address v0.0.0-20230922120653-901b9ae4061a
	github.com/packer-community/winrmcp v0.0.0-20180921211025-c76d91c1e7db
	github.com/pkg/errors v0.9.1
	github.com/posener/complete v1.2.3
	github.com/rs/zerolog v1.34.0
	github.com/spf13/afero v1.14.0
	github.com/spf13/cobra v1.9.1
	github.com/spf13/pflag v1.0.6
	github.com/stretchr/testify v1.10.0
	github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common v1.0.588
	github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/sts v1.0.588
	github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/tag v1.0.233
	github.com/tencentyun/cos-go-sdk-v5 v0.7.29
	github.com/tombuildsstuff/giovanni v0.15.1
	github.com/vincent-petithory/dataurl v1.0.0
	github.com/xanzy/ssh-agent v0.3.1
	github.com/xlab/treeprint v0.0.0-20161029104018-1d6e34225557
	github.com/zclconf/go-cty v1.16.2
	github.com/zclconf/go-cty-debug v0.0.0-20240509010212-0d6042c53940
	github.com/zclconf/go-cty-yaml v1.1.0
	go.opentelemetry.io/otel v1.35.0
	go.opentelemetry.io/otel/trace v1.35.0
	golang.org/x/crypto v0.37.0
	golang.org/x/exp v0.0.0-20230905200255-921286631fa9
	golang.org/x/mod v0.24.0
	golang.org/x/net v0.39.0
	golang.org/x/oauth2 v0.29.0
	golang.org/x/sys v0.32.0
	golang.org/x/term v0.31.0
	golang.org/x/text v0.24.0
	google.golang.org/api v0.231.0
	google.golang.org/genproto v0.0.0-20250428153025-10db94c68c34
	google.golang.org/grpc v1.72.0
	google.golang.org/protobuf v1.36.6
	gopkg.in/yaml.v3 v3.0.1
	k8s.io/api v0.23.4
	k8s.io/apimachinery v0.23.4
	k8s.io/client-go v0.23.4
	k8s.io/utils v0.0.0-20211116205334-6203023598ed
)

require (
	cel.dev/expr v0.23.1 // indirect
	cloud.google.com/go v0.121.0 // indirect
	cloud.google.com/go/auth v0.16.1 // indirect
	cloud.google.com/go/auth/oauth2adapt v0.2.8 // indirect
	cloud.google.com/go/compute/metadata v0.6.0 // indirect
	cloud.google.com/go/iam v1.5.2 // indirect
	cloud.google.com/go/longrunning v0.6.7 // indirect
	cloud.google.com/go/monitoring v1.24.2 // indirect
	github.com/Azure/go-autorest v14.2.0+incompatible // indirect
	github.com/Azure/go-autorest/autorest/adal v0.9.18 // indirect
	github.com/Azure/go-autorest/autorest/azure/cli v0.4.4 // indirect
	github.com/Azure/go-autorest/autorest/date v0.3.0 // indirect
	github.com/Azure/go-autorest/autorest/to v0.4.0 // indirect
	github.com/Azure/go-autorest/autorest/validation v0.3.1 // indirect
	github.com/Azure/go-autorest/logger v0.2.1 // indirect
	github.com/Azure/go-autorest/tracing v0.6.0 // indirect
	github.com/Azure/go-ntlmssp v0.0.0-20200615164410-66371956d46c // indirect
	github.com/ChrisTrenkamp/goxpath v0.0.0-20190607011252-c5096ec8773d // indirect
	github.com/GoogleCloudPlatform/opentelemetry-operations-go/detectors/gcp v1.27.0 // indirect
	github.com/GoogleCloudPlatform/opentelemetry-operations-go/exporter/metric v0.51.0 // indirect
	github.com/GoogleCloudPlatform/opentelemetry-operations-go/internal/resourcemapping v0.51.0 // indirect
	github.com/Masterminds/goutils v1.1.1 // indirect
	github.com/Masterminds/semver/v3 v3.1.1 // indirect
	github.com/Masterminds/sprig/v3 v3.2.2 // indirect
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/agnivade/levenshtein v1.2.1 // indirect
	github.com/antchfx/xmlquery v1.3.5 // indirect
	github.com/antchfx/xpath v1.1.10 // indirect
	github.com/apparentlymart/go-textseg/v15 v15.0.0 // indirect
	github.com/armon/go-metrics v0.0.0-20180917152333-f0300d1749da // indirect
	github.com/armon/go-radix v1.0.0 // indirect
	github.com/aws/aws-sdk-go v1.55.7 // indirect
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.5.1 // indirect
	github.com/aws/aws-sdk-go-v2/config v1.25.8 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.16.6 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.2.5 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.5.5 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.7.1 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.2.5 // indirect
	github.com/aws/aws-sdk-go-v2/service/iam v1.27.5 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.10.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.2.5 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/endpoint-discovery v1.8.5 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.10.5 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.16.5 // indirect
	github.com/aws/aws-sdk-go-v2/service/sqs v1.28.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.17.5 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.20.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.25.6 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/bgentry/go-netrc v0.0.0-20140422174119-9fd32a8b3d3d // indirect
	github.com/cenkalti/backoff/v3 v3.0.0 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/cloudflare/circl v1.6.1 // indirect
	github.com/cncf/xds/go v0.0.0-20250501225837-2ac532fd4443 // indirect
	github.com/dimchansky/utfbom v1.1.1 // indirect
	github.com/dylanmei/iso8601 v0.1.0 // indirect
	github.com/envoyproxy/go-control-plane/envoy v1.32.4 // indirect
	github.com/envoyproxy/protoc-gen-validate v1.2.1 // indirect
	github.com/fatih/color v1.18.0 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/go-ini/ini v1.67.0 // indirect
	github.com/go-jose/go-jose/v3 v3.0.3 // indirect
	github.com/go-jose/go-jose/v4 v4.1.0 // indirect
	github.com/go-logr/logr v1.4.2 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/gobwas/glob v0.2.3 // indirect
	github.com/gofrs/uuid v4.0.0+incompatible // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang-jwt/jwt/v4 v4.5.1 // indirect
	github.com/golang/groupcache v0.0.0-20241129210726-2c02b8208cf8 // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/google/gofuzz v1.1.0 // indirect
	github.com/google/s2a-go v0.1.9 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.3.6 // indirect
	github.com/googleapis/gnostic v0.5.5 // indirect
	github.com/gorilla/mux v1.8.1 // indirect
	github.com/hashicorp/go-immutable-radix v1.0.0 // indirect
	github.com/hashicorp/go-rootcerts v1.0.2 // indirect
	github.com/hashicorp/go-safetemp v1.0.0 // indirect
	github.com/hashicorp/go-secure-stdlib/parseutil v0.1.6 // indirect
	github.com/hashicorp/go-secure-stdlib/strutil v0.1.2 // indirect
	github.com/hashicorp/go-slug v0.16.3 // indirect
	github.com/hashicorp/go-sockaddr v1.0.2 // indirect
	github.com/hashicorp/golang-lru v0.5.1 // indirect
	github.com/hashicorp/serf v0.9.6 // indirect
	github.com/hashicorp/terraform-plugin-log v0.9.0 // indirect
	github.com/hashicorp/yamux v0.0.0-20181012175058-2f1d1f20f75d // indirect
	github.com/huandu/xstrings v1.3.3 // indirect
	github.com/imdario/mergo v0.3.13 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/klauspost/compress v1.18.0 // indirect
	github.com/manicminer/hamilton-autorest v0.2.0 // indirect
	github.com/masterzen/simplexml v0.0.0-20190410153822-31eea3082786 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-runewidth v0.0.16 // indirect
	github.com/mitchellh/go-testing-interface v1.14.1 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/mozillazg/go-httpheader v0.3.0 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/nu7hatch/gouuid v0.0.0-20131221200532-179d4d0c4d8d // indirect
	github.com/oklog/run v1.0.0 // indirect
	github.com/olekukonko/tablewriter v0.0.5 // indirect
	github.com/peterh/liner v1.2.2 // indirect
	github.com/planetscale/vtprotobuf v0.6.1-0.20240319094008-0393e58bdf10 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/prometheus/client_golang v1.22.0 // indirect
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/prometheus/common v0.63.0 // indirect
	github.com/prometheus/procfs v0.16.1 // indirect
	github.com/rcrowley/go-metrics v0.0.0-20250401214520-65e299d6c5c9 // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	github.com/ryanuber/go-glob v1.0.0 // indirect
	github.com/shopspring/decimal v1.3.1 // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	github.com/spf13/cast v1.7.1 // indirect
	github.com/spiffe/go-spiffe/v2 v2.5.0 // indirect
	github.com/tchap/go-patricia/v2 v2.3.2 // indirect
	github.com/ulikunitz/xz v0.5.12 // indirect
	github.com/vmihailenco/msgpack/v5 v5.3.5 // indirect
	github.com/vmihailenco/tagparser/v2 v2.0.0 // indirect
	github.com/xeipuuv/gojsonpointer v0.0.0-20190905194746-02993c407bfb // indirect
	github.com/xeipuuv/gojsonreference v0.0.0-20180127040603-bd5ef7bd5415 // indirect
	github.com/yashtewari/glob-intersection v0.2.0 // indirect
	github.com/zeebo/errs v1.4.0 // indirect
	go.opentelemetry.io/auto/sdk v1.1.0 // indirect
	go.opentelemetry.io/contrib/detectors/gcp v1.35.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/github.com/aws/aws-sdk-go-v2/otelaws v0.46.1 // indirect
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.60.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.60.0 // indirect
	go.opentelemetry.io/otel/metric v1.35.0 // indirect
	go.opentelemetry.io/otel/sdk v1.35.0 // indirect
	go.opentelemetry.io/otel/sdk/metric v1.35.0 // indirect
	golang.org/x/sync v0.13.0 // indirect
	golang.org/x/time v0.11.0 // indirect
	golang.org/x/tools v0.32.0 // indirect
	golang.org/x/xerrors v0.0.0-20240903120638-7835f813f4da // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20250428153025-10db94c68c34 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250428153025-10db94c68c34 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/ini.v1 v1.66.2 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	k8s.io/klog/v2 v2.30.0 // indirect
	k8s.io/kube-openapi v0.0.0-20211115234752-e816edb12b65 // indirect
	sigs.k8s.io/json v0.0.0-20211020170558-c049b76a60c6 // indirect
	sigs.k8s.io/structured-merge-diff/v4 v4.2.1 // indirect
	sigs.k8s.io/yaml v1.4.0 // indirect
)

replace github.com/hashicorp/hcl/v2 v2.20.1 => github.com/opentofu/hcl/v2 v2.0.0-20240814143621-8048794c5c52

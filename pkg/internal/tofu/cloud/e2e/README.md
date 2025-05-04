# How to run tests

To run them, use:
```
TFE_TOKEN=<token> TFE_HOSTNAME=<hostname> TF_ACC=1 go test  ./internal/cloud/e2e/... -ldflags "-X \"github.com/opentofu/opentofu/version.Prerelease=<PRE-RELEASE>\""
```

Required flags
* `TF_ACC=1`. This variable is used as part of tofu for tests that make 
  external network calls. This is needed to run these tests. Without it, the
  tests do not run.
* `TFE_TOKEN=<admin token>` and `TFE_HOSTNAME=<hostname>`. The helpers
for these tests require admin access to a TFC/TFE instance.
* `-timeout=30m`. Some of these tests take longer than the default 10m timeout for `go test`.

### Flags

* Use the `-v` flag for normal verbose mode.
* Use the `-tfoutput` flag to print the tofu output to standard out.
*  Use `-ldflags` to change the version Prerelease to match a version
available remotely. Some behaviors rely on the exact local version OpenTofu
being available in TFC/TFE, and manipulating the Prerelease during build is
often the only way to ensure this.
[(More on `-ldflags`.)](https://www.digitalocean.com/community/tutorials/using-ldflags-to-set-version-information-for-go-applications)

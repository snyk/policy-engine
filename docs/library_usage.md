# Use as a library

This document describes each of the main components of the `policy-engine`
library. See the [`run` command](../cmd/run.go) for an end-to-end example that uses the
components together.

- [Use as a library](#use-as-a-library)
  - [Parsing IaC configurations](#parsing-iac-configurations)
    - [`Detector`](#detector)
      - [The `Detectable` interface](#the-detectable-interface)
      - [Recursing through directory contents](#recursing-through-directory-contents)
        - [Examples](#examples)
    - [`Loader`](#loader)
    - [Example](#example)
      - [Obtaining input types for the DetectorByInputTypes function](#obtaining-input-types-for-the-detectorbyinputtypes-function)
    - [Error handling](#error-handling)
  - [Custom resource resolution](#custom-resource-resolution)
  - [Evaluating policies](#evaluating-policies)
    - [`engine.Engine`](#engineengine)
    - [`data.Provider`](#dataprovider)
      - [`data.FSProvider()`](#datafsprovider)
      - [`data.LocalProvider()`](#datalocalprovider)
    - [Example](#example-1)
    - [Error handling](#error-handling-1)
  - [Post-processing](#post-processing)
    - [Source code location and line numbers](#source-code-location-and-line-numbers)
      - [Example](#example-2)
    - [Filtering down resources](#filtering-down-resources)
      - [Example](#example-3)

## Parsing IaC configurations

The `input` package provides facilities to detect and load IaC configurations and to
transform them into the format used by the `engine` package.

### `Detector`

The `input` package contains several `Detector` implementations that are responsible for
detecting and parsing IaC configurations. Callers should use the `DetectorByInputTypes`
function to obtain a `Detector` for some set of input types:

```go
detector, err := input.DetectorByInputTypes(
  input.Types{input.Auto},
)
if err != nil {
  return err
}
```

#### The `Detectable` interface

The input to the detector will be one of the concrete `Detectable` implementations:

```go
input.File
input.Directory
```

You can obtain these types either by instantiating them directly for a specific path,
like:

```go
// Note that these types take an afero.Fs: https://github.com/spf13/afero
f := input.File{
  Path: "path/to/some_file.json",
  Fs: afero.OsFs{},
}

d := input.Directory{
  Path: "path/to/some_directory",
  Fs: afero.OsFs{},
}
```

There is also a helper which will check whether or not a path points to a directory and
return the appropriate type:

```go
d := NewDetectable(afero.OsFs{}, "some/path")
```

#### Recursing through directory contents

The `input.Directory` type has a `Walk()` method that can be used to recurse through
its contents. `Walk()` takes a `WalkFunc` function, which is invoked with each
`input.Detectable` in the directory tree. If `WalkFunc` returns `true`, `Walk` will not
recurse further in the current path. If `WalkFunc` returns a non-nil `error`, `Walk`
will halt and bubble up the error.

`WalkFunc` also takes a `depth` argument which can be used to stop recursing after a
certain depth. `depth` is a 0-based representation of how many levels deep the recursion
is relative to the initial call, meaning that `depth` will be `0` for the children of
the directory.

##### Examples

A simple example that uses the output of `loader.Load()` (described below) to not
recurse into directories that have already been loaded:

```go
loader := input.NewLoader(detector)
dir := input.Directory{
  Path: "some_directory",
  Fs: afero.OsFs{},
}
walkFunc := func(d Detectable, depth int) (bool, error) {
  // loader.Load returns true if the detectable contained an IaC configuration and was
  // successfully loaded.
  return loader.Load(d, input.DetectOptions{})
}
if err := dir.Walk(walkFunc); err != nil {
  // ...
}
```

An example that builds on the previous one to stop recursing after a certain depth:

```go
loader := input.NewLoader(detector)
dir := input.Directory{
  Path: "some_directory",
  Fs: afero.OsFs{},
}
walkFunc := func(d Detectable, depth int) (bool, error) {
  loaded, err := loader.Load(d, input.DetectOptions{})
  if err != nil {
    return true, err
  }
  return loaded || depth > 3
}
if err := dir.Walk(walkFunc); err != nil {
  // ...
}
```

### `Loader`

The `Loader` type is responsible for invoking a detector on some input, storing the
parsed IaC configuration, and later producing a `[]models.State` with all of its
configurations for use with the `engine` package.

```go
loader := input.NewLoader(detector)
loaded, err := loader.Load(*input.File{
  Fs: afero.OsFs{},
  Path: "cloudformation.yaml",
})
if err != nil {
  // ...
}
if !loaded {
  // ...
}
states := loaded.ToStates()
```

### Example

This example treats all errors as non-fatal and, instead, tracks them in a `map` by
filepath.

```go
package main

import (
  "errors"
  "fmt"

  "github.com/snyk/policy-engine/pkg/input"
)

func example(paths []string) {
  // Initialize the detector
  detector, err := input.DetectorByInputTypes(
    input.Types{input.Auto},
  )
  if err != nil {
    // ...
  }
  loader := input.NewLoader(detector)
  // Tracking errors by filepath
  errorsByPath := map[string]error{}
  // Defining a function to reduce code duplication
  load := func(d input.Detectable) bool {
    loaded, err := loader.Load(d, input.DetectOptions{})
    if err != nil {
      errorsByPath[d.GetPath()] = err
    }
    return loaded
  }
	fsys := afero.OsFs{}
  for _, p := range paths {
		detectable, err := input.NewDetectable(fsys, p)
    if err != nil {
      errorsByPath[p] = err
    }
    if loaded := load(detectable); loaded {
      continue
    }
    if dir, ok := detectable.(input.Directory); ok {
      // Our WalkFunc will only traverse three levels deep into the file tree.
      walkFunc := func(d input.Detectable, depth int) (bool, error) {
        loaded := load(d)
        return loaded || depth >= 3, nil
      }
      if err := dir.Walk(walkFunc); err != nil {
        return errorsByPath[p] = err
      }
    } else if _, ok := errorsByPath[p]; !ok {
      // This condition hits if the path:
      // * points to a file
      // * was not loaded as an IaC configuration
      // * does not already have another error associated with it
      errorsByPath[p] = fmt.Errorf("No recognized input in given file")
    }
	}
  if loader.Count() < 1 {
    // ...
  }
  // Add any non-fatal errors the loaders encountered
  for p, errs := range loader.Errors() {
    errorsByPath[p] = append(errorsByPath[p], errs...)
  }
  // Transform the loaded configurations into a slice of State structs
  states := loader.ToStates()
  // ...
}
```

#### Obtaining input types for the DetectorByInputTypes function

The `input` package has a `SupportedInputTypes` variable that defines which input types
it can parse. You can use the `input.SupportedInputTypes.FromString(inputType)` method
to translate a string representation of an input type (for example from CLI arguments
or a configuration file) into an `input.Type` object which can be used with the
`DetectorByInputTypes` function.

### Error handling

The errors returned by the `input` package can be differentiated with the `errors.Is()`
function from the [errors standard library package](https://pkg.go.dev/errors). All of
these errors are defined in [`pkg/input/errors.go`](../pkg/input/errors.go) and have
inline documentation.

| Error                        |
| :--------------------------- |
| `UnsupportedInputType`       |
| `UnableToRecognizeInputType` |
| `UnableToResolveLocation`    |
| `UnrecognizedFileExtension`  |
| `FailedToParseInput`         |
| `InvalidInput`               |
| `UnableToReadFile`           |
| `UnableToReadDir`            |
## Custom resource resolution

The library's caller can customize the behavior of the [`snyk.query`
builtin](policy_spec.md#snykqueryquery) using Golang functions injected into
EngineOptions. The main use case of this is to fetch resources from places other
than the input.

As a concrete example, let's imagine a CLI to scan IaC files for security
issues. Policy authors might want to write policies that mix cloud resources
with static config, to enrich the static analysis with some dynamic context, and
potentially suppress noisy false positives (that are only false in the context
of some concrete environments).

First, they'll implement the `policy.ResourcesResolver` function signature:

```go
func getCloudResources(ctx context.Context, query policy.ResourcesQuery) (policy.ResourcesResult, error) {
	// The "region" input scope field will not be set by IaC config loaders. If it
	// is present, the resolver chain will be invoked for that query, leading us
	// here. If it is still not set, then this query must be for something else,
	// and we should pass on it.
	if _, ok := query.Scope["region"]; !ok {
		return policy.ResourcesResult{ScopeFound: false}, nil
	}

	resources := fetchResourcesFromCloud(query.ResourceType, query.Scope["region"])
	return policy.ResourcesResult{
		ScopeFound: true,
		Resources:  resources,
	}, nil
}

```

Then, they can inject that into the engine's resolver chain at evaluation time:

```go
  engine, err := upe.NewEngine(ctx, &upe.EngineOptions{
    ...
  })
  results := engine.Eval(ctx, &engine.EvalOptions{
    ...
    ResourcesResolver: policy.ResourcesResolver(getCloudResources),
  })
```

Policies that make use of the "region" input scope field, which will not be set
by IaC-specific config loaders, such as:

```
resources := snyk.query({
  "resource_type": "aws_cloudtrail",
  "scope": {
    "region": "us-east-1",
  },
})
```

Will trigger the resolver chain, causing the user-defined `getCloudResources` to
be called. This function can then fetch the requested resources from the Cloud
API directly.

## Evaluating policies

### `engine.Engine`

The `Engine` type is responsible for evaluating some `State`s with a given set of
policies.

### `data.Provider`

The `data.Provider` type is a function that provides parsed OPA modules and data
documents to some consumer. The `data` package includes a few `Provider`
implementations.

#### `data.FSProvider()`

`data.FSProvider()` produces a provider function for the given filesystem. This is
useful for policies that are embedded via the `go:embed` directive:

```go
package main

import (
  "embed"

  "github.com/snyk/policy-engine/pkg/data"
)

//go:embed policies
var policiesFS embed.FS

// The second argument here is the name of the directory where the provider should
// search for policies and data documents.
var policiesProvider = data.FSProvider(policiesFS, "policies")

func main() {
  // ...
}
```

#### `data.LocalProvider()`

`data.LocalProvider()` produces a provider function over some local path. That path
could point to either a file or directory.

```go
package main

import "github.com/snyk/policy-engine/pkg/data"

func main() {
  // ...
  providers := make([]data.Provider, len(paths))
  for idx, path := range paths {
    providers[idx] = data.LocalProvider(path)
  }
}
```

### Example

```go
package main

import "github.com/snyk/policy-engine/pkg/engine"

func main() {
  ctx := context.Background()
  // ...
  eng, err := engine.NewEngine(ctx, &engine.EngineOptions{
    // Providers contains functions that produce parsed OPA modules or data documents.
    // See above for descriptions of the providers included in this library.
    Providers: providers,
    // This option is used to determine which policies are executed. When this option is
    // empty or unspecified, all policies will be run.
    RuleIDs:   selectedPolicies,
    // This is an optional instance of the logger.Logger interface. This interface is
    // compatible with the one provided by the snyk/go-common library. The logger
    // package also contains an implementation of this interface.
    Logger:    logger,
    // This is an optional instance of the metrics.Metrics interface. This interface is
    // compatible with the one provided by the snyk/go-common library. The metrics
    // package also contains an implementation of this interface.
    Metrics:   m,
    // ResourceResolvers is a list of functions that return a resource state for
    // the given ResourceRequest. They will be invoked in order until a result is
    // returned with ScopeFound set to true.
    ResourcesResolvers []policy.ResourcesResolver
  })
  if err != nil {
    // Checking for specific errors
    switch {
    case errors.Is(err, engine.FailedToLoadRegoAPI):
      // ...
    case errors.Is(err, engine.FailedToLoadRules):
      // ...
    default:
      // ...
    }
  }
  // This function returns a *models.Results
  results := eng.Eval(ctx, &engine.EvalOptions{
    // Inputs is a []models.State, like the output of the loader.ToStates()
    // described above.
    Inputs: states,
  })
}
```

### Error handling

The errors returned by the `NewEngine` function can be differentiated with the
`errors.Is()` function from the
[errors standard library package](https://pkg.go.dev/errors). All of these errors are
defined in [`pkg/engine/errors.go`](../pkg/engine/errors.go) and have inline
documentation.

**NOTE** that `Eval` does not currently return an `error`. Errors that occur during rule
evaluation will be returned in the `Errors` field of the corresponding `RuleResults`
model in the output.

| Error                 |
| :-------------------- |
| `FailedToLoadRegoAPI` |
| `FailedToLoadRules`   |
| `FailedToCompile`     |

## Post-processing of results

### Source code location and line numbers

The `AddSourceLocs` function from the policy engine's `postprocess` package
performs a post-processing step that annotates results with source code
locations, like:

```json
{
  ...
  "location": [
    {
      "filepath": "examples/main.tf",
      "line": 29,
      "column": 1
    }
  ],
  ...
}
```

#### Example

Building on top of both the ["parsing IaC configurations" example](#example) and the
["evaluating policies" example](#example-1):

```go
package main

import (
    "github.com/snyk/policy-engine/pkg/input",
    "github.com/snyk/policy-engine/pkg/engine"
    "github.com/snyk/policy-engine/pkg/postprocess"
)

func main() {
    // Code that initializes a loader and produces results with engine from the
    // previous examples
    // ...

    // AddSourceLocs modifies the results object in-place to add source
    // code locations to resources and properties for supported input types.
    postprocess.AddSourceLocs(results, loader)
}
```

### Filtering down resources

You can use the `ResourceFilter` function `postprocess` to limit the resources
appearing in the output.  This filters down the resources state in the output
to only the matching resources.  It also narrows down the rule results to that
refer to at least one of these matching resources.

#### Example

```go
var results *models.Results
// Code to produce the results
// ...
postprocess.ResourceFilter(results, func(resource *models.ResourceState) bool {
	if region, ok := resource.Meta["region"].(string); ok {
		strings.Contains(region, "us-gov")
	}
	return false
})
```

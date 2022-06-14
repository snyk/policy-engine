# Use as a library

This document describes each of the main components of the `policy-engine`
library. See the [`run` command](cmd/run.go) for an end-to-end example that uses the
components together.

- [Use as a library](#use-as-a-library)
  - [Parsing IaC configurations](#parsing-iac-configurations)
    - [`ConfigurationLoader`](#configurationloader)
      - [`LocalConfigurationLoader`](#localconfigurationloader)
    - [`LoadedConfigurations`](#loadedconfigurations)
    - [Example](#example)
      - [Obtaining input types for the InputTypes option](#obtaining-input-types-for-the-inputtypes-option)
    - [Error handling](#error-handling)
  - [Evaluating policies](#evaluating-policies)
    - [`engine.Engine`](#engineengine)
    - [`data.Provider`](#dataprovider)
      - [`data.FSProvider()`](#datafsprovider)
      - [`data.LocalProvider()`](#datalocalprovider)
    - [Example](#example-1)
    - [Error handling](#error-handling-1)
  - [Source code location and line numbers](#source-code-location-and-line-numbers)
    - [Example](#example-2)

## Parsing IaC configurations

### `ConfigurationLoader`

The `ConfigurationLoader` concept from the `loader` package is the main entrypoint to
parsing IaC configurations into the format expected by the policy engine's policy evaluation code.

#### `LocalConfigurationLoader`

Currently, there is only one implementation of `ConfigurationLoader`, called
`LocalConfigurationLoader`, and it is used to parse IaC configurations from disk:

### `LoadedConfigurations`

The `LoadedConfigurations` type is the output of a `ConfigurationLoader`. It contains
methods to introspect the loaded configurations and transform them into the the policy engine input
format.

### Example

```go
package main

import (
  "errors"

  "github.com/snyk/policy-engine/pkg/inputs"
  "github.com/snyk/policy-engine/pkg/loader"
)

func main() {
  // Initialize the loader
  configLoader := loader.LocalConfigurationLoader(loader.LoadPathsOptions{
    // Paths is a []string that contains paths where the loader should search for IaC
    // configurations
    Paths:       args,
    // InputTypes sets which input types the loader should attempt to parse. The
    // loader.Auto input type includes all known IaC formats.
    InputTypes:  inputs.InputTypes{inputType},
    // By default, this loader will respect .gitignore files that it finds. This loader
    // searches upwards through parent directories until it finds a .git directory. If
    // a .git directory is found, it will then search for .gitignore files in any
    // directories that are both within the repository and contained within the input
    // paths specified above.
    // Setting this option to true will disable that behavior.
    NoGitIgnore: false,
  })

  // Invoke the loader, returning a LoadedConfigurations struct
  loadedConfigs, err := configLoader()
  if err != nil {
    // Checking for specific errors
    switch {
    case errors.Is(err, loader.NoLoadableInputs):
      // ...
    case errors.Is(err, loader.UnrecognizedFileExtension):
      // ...
    default:
      // ...
    }
  }
  // Transform the loaded configurations into a slice of State structs
  states := loadedConfigs.ToStates()
  // ...
}
```

#### Obtaining input types for the InputTypes option

The `loader` package has a `SupportedInputTypes` variable that defines which input types
it can parse. You can use the `loader.SupportedInputTypes.FromString(inputType)` method
to translate a string representation of an input type (for example from CLI arguments
or a configuration file) into an `InputType` object which can be used in the
`LoadPathsOptions.InputTypes` field.

### Error handling

The errors returned by the `ConfigurationLoader` function can be differentiated with
either the `errors.Is()` function or the `errors.As()` function (or just a type cast)
from the [errors standard library package](https://pkg.go.dev/errors). All of these
errors are defined in [`pkg/loader/errors.go`](../pkg/loader/errors.go) and have
inline documentation.

| Error                        | Differentiated with      |
| :--------------------------- | :----------------------- |
| `NoLoadableInputs`           | `errors.Is`              |
| `UnableToRecognizeInputType` | `errors.Is`              |
| `FailedToProcessInput`       | `errors.As` or type cast |
| `UnsupportedInputType`       | `errors.Is`              |
| `UnableToResolveLocation`    | `errors.Is`              |
| `UnrecognizedFileExtension`  | `errors.Is`              |
| `FailedToParseInput`         | `errors.Is`              |
| `InvalidInput`               | `errors.Is`              |
| `UnableToReadFile`           | `errors.Is`              |
| `UnableToReadDir`            | `errors.Is`              |
| `UnableToReadStdin`          | `errors.Is`              |

**NOTE** that `FailedToProcessInput` will always wrap one of the other errors, so it
does not need to be handled explicitly unless its `Path` attribute is needed.

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
  engine, err := engine.NewEngine(ctx, &engine.EngineOptions{
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
  })
  if err != nil {
    // Checking for specific errors
    switch {
    case errors.Is(err, loader.FailedToLoadRegoAPI):
      // ...
    case errors.Is(err, loader.FailedToLoadRules):
      // ...
    default:
      // ...
    }
  }
  // This function returns a *models.Results
  results := engine.Eval(ctx, &engine.EvalOptions{
    // Inputs is a []models.State, like the output of the loadedConfigs.ToStates()
    // described above.
    Inputs: states,
  })
}
```

### Error handling

The errors returned by the `NewEngine` function can be differentiated with the
`errors.Is()` function from the
[errors standard library package](https://pkg.go.dev/errors). All of these errors are
defined in [`pkg/engine/errors.go`](../pkg/loader/errors.go) and have inline
documentation.

**NOTE** that `Eval` does not currently return an `error`. Errors that occur during rule
evaluation will be returned in the `Errors` field of the corresponding `RuleResults`
model in the output.

| Error                 | Differentiated with |
| :-------------------- | :------------------ |
| `FailedToLoadRegoAPI` | `errors.Is`         |
| `FailedToLoadRules`   | `errors.Is`         |
| `FailedToCompile`     | `errors.Is`         |

## Source code location and line numbers

The `AnnotateResults` function from the policy engine's `loader` package performs a post-processing
step that annotates results with source code locations, like:

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

### Example

Building on top of both the ["parsing IaC configurations" example](#example) and the
["evaluating policies" example](#example-1):

```go
package main

import (
    "github.com/snyk/policy-engine/pkg/loader",
    "github.com/snyk/policy-engine/pkg/engine"
)

func main() {
    // Code that initializes loadedConfigs and produces results with engine from the
    // previous examples
    // ... 

    // AnnotateResults modifies the results object in-place to add source code locations
    // to resources and properties for supported input types.
    loader.AnnotateResults(loadedConfigs, results)
}
```

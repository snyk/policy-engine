# Unified Policy Engine

## Building & running

    go build
    ./unified-policy-engine
    
## Use as a library

This section describes each of the main components of the `unified-policy-engine`
library. See the [`run` command](cmd/run.go) for an end-to-end example that uses the 
components together.

### Parsing IaC configurations

#### `ConfigurationLoader`

The `ConfigurationLoader` concept from the `loader` package is the main entrypoint to
parsing IaC configurations into the format expected by UPE's rule evaluation code.

##### `LocalConfigurationLoader`

Currently, there is only one implementation of `ConfigurationLoader`, called
`LocalConfigurationLoader`, and it is used to parse IaC configurations from disk:

#### `LoadedConfigurations`

The `LoadedConfigurations` type is the output of a `ConfigurationLoader`. It contains
methods to introspect the loaded configurations and transform them into the UPE input
format.

#### Example

```go
package main

import "github.com/snyk/unified-policy-engine/pkg/loader"

func main() {
  // Initialize the loader
  configLoader := loader.LocalConfigurationLoader(loader.LoadPathsOptions{
    // Paths is a []string that contains paths where the loader should search for IaC
    // configurations
    Paths:       args,
    // InputTypes sets which input types the loader should attempt to parse. The
    // loader.Auto input type includes all known IaC formats.
    InputTypes:  []loader.InputType{inputType},
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
    // ...
  }
  // Transform the loaded configurations into a slice of State structs
  states := loadedConfigs.ToStates()
  // ...
}
```

### Evaluating rules

#### `upe.Engine`

The `Engine` type is responsible for evaluating some `State`s with a given set of rules.

#### `data.Provider`

The `data.Provider` type is a function that provides parsed OPA modules and data
documents to some consumer. The `data` package includes a few `Provider` implementations.

##### `data.FSProvider()`

`data.FSProvider()` produces a provider function for the given filesystem. This is
useful for rules that are embedded via the `go:embed` directive:

```go
package main

import (
  "embed"

  "github.com/snyk/unified-policy-engine/pkg/data"
)

//go:embed rules
var rulesFS embed.FS

// The second argument here is the name of the directory where the provider should
// search for rules and data documents.
var rulesProvider = data.FSProvider(rulesFS, "rules")

func main() {
  // ...
}
```

##### `data.LocalProvider()`

`data.LocalProvider()` produces a provider function over some local path. That path
could point to either a file or directory.

```go
package main

import "github.com/snyk/unified-policy-engine/pkg/data"

func main() {
  // ...
  providers := make([]data.Provider, len(paths))
  for idx, path := range paths {
    providers[idx] = data.LocalProvider(path)
  }
}
```

#### Example

```go
package main

import "github.com/snyk/unified-policy-engine/pkg/upe"

func main() {
  ctx := context.Background()
  // ...
  engine, err := upe.NewEngine(ctx, &upe.EngineOptions{
    // Providers contains functions that produce parsed OPA modules or data documents.
    // See above for descriptions of the providers included in this library.
    Providers: providers,
    // This option is used to determine which rules are executed. When this option is
    // empty or unspecified, all rules will be run.
    RuleIDs:   selectedRules,
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
    // ...
  }
  // This function returns a *models.Results
  results, err := engine.Eval(ctx, &upe.EvalOptions{
    // Inputs is a []models.State, like the output of the loadedConfigs.ToStates()
    // described above.
    Inputs: states,
  })
  if err != nil {
    // ...
  }
}
```

## Rule Syntax Tutorial

We will walk through the rules in the examples directory, starting out with
simple rules and gradually adding concepts.

### Examples

#### Simple rules part 1

[examples/01-simple.rego](examples/01-simple.rego)

#### Simple rules part 2: Returning attributes

[examples/02-simple-attributes.rego](examples/02-simple-attributes.rego)

#### Advanced rules part 1

[examples/02-advanced.rego](examples/03-advanced.rego)

#### Advanced rules part 2: Adding compliant resource info

[examples/03-advanced.rego](examples/04-advanced.rego)

#### Advanced rules part 3: Correlating resources

[examples/04-advanced.rego](examples/05-advanced.rego)

#### Advanced rules part 4: Returning attributes

[examples/06-advanced.rego](examples/06-advanced.rego)

#### Missing resources

[examples/07-missing.rego](examples/07-missing.rego)

### Reference

#### Info objects

Info objects have different fields depending in which context they occur.

`deny[info]` fields:

 -  `message`: Message string detailing the issue.  **Required.**
 -  `resource`: Resource associated with the issue.
 -  `attributes`: List of [attribute paths](#attribute-paths).
 -  `resource_type`: May be used to indicate the resource type in case of a
    missing resource.
 -  `correlation`: May be used to override the correlation the policy engine
    uses to relate issues.  Defaults to `.resource.id`.

`resources[info]` fields:

 -  `resource`: Resource associated with the issue.  **Required.**
 -  `attributes`: List of [attribute paths](#attribute-paths).
 -  `correlation`: May be used to override the correlation the policy engine
    uses to relate issues.  Defaults to `.resource.id`.

#### Attribute paths

Attribute paths are JSON arrays of strings and numbers.  They items in these
arrays correspond to indices in objects and arrays respectively.

Considering the following JSON attributes:

```json
{
  "ingress": [
    {
      "from_port": 22,
      "to_port": 22
    }
  ]
}
```

Then the `from_port` path would be `["ingress", 0, "from_port"]`.

#### snyk API

 -  `snyk.resources(resource_type)`:
    Returns a object of resource IDs to resources of the requested type.

## Testing rules

In order to test rules, we want to generate _fixtures_ so that we freeze in
the processed input generated by the Unified Policy Engine.  This allows us
to use standard OPA tooling.

You can generate a fixture using the `fixture` command.  For example, we can
generate a fixture for the example terraform file we are using like this:

    ./unified-policy-engine fixture examples/main.tf >examples/tests/fixture.json

Fixtures can also be generated using other applications.  The important bit is
that a fixture should provide a `mock_input` rule which represents the input to
be used for the test.

This allows us to import and use the fixture in a test:

[examples/tests/advanced-rule-test.rego](examples/tests/advanced-rule-test.rego)

Running the tests:

    ./unified-policy-engine -d examples test

We can also run using vanilla OPA.  This requires us to pass in the
[rego/](rego/) directory as well:

    opa test examples rego

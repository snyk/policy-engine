# `arm` package

`policy-engine` has some support for evaluating [ARM template
expressions](https://learn.microsoft.com/en-us/azure/azure-resource-manager/templates/syntax),
but there are some known limitations:

* Not all functions are supported. The source of truth for function support is
  [the keys of `EvaluationContext.funcs` set in `NewEvaluationContext()` in `eval.go`](./eval.go).
   * Not all types are supported. These will be added as we add support for
     functions that make use of these types.
* Template expressions in resource-identifying fields (type, name, and tags) are
  not evaluated.
* Template expressions in variables definitions are not evaluated.
* Support for functions that require "deployment context" such as
  `resourceGroup()` and `resourceId()` is limited by definition: `policy-engine`
  returns stubs for return value fields that it can't know about.

Failures in expression evaluation are non-fatal, but may lead to false
positives/negatives in policy evaluation if the result of the expression would
have been significant to the policy.

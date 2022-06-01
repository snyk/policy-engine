package upe

import (
	"errors"
)

// FailedToLoadRegoAPI indicates that an error occurred while initializing the snyk
// Rego API.
var FailedToLoadRegoAPI = errors.New("Failed to load the snyk Rego API")

// FailedToLoadRules indicates that an error occurred while consuming the rego and data
// producers provided to the engine.
var FailedToLoadRules = errors.New("Failed to load rules")

// FailedToCompile indicates that more than the maximum number of errors occurred during
// the compilation stage.
var FailedToCompile = errors.New("Failed to compile rules")

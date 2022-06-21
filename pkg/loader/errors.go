package loader

import (
	"errors"
	"fmt"
)

////////////////////////////////
// ConfigurationLoader errors //
////////////////////////////////

// NoLoadableInputs indicates that the loader could not find any recognized
// IaC configurations with the given parameters.
var NoLoadableInputs = errors.New("No recognized inputs with the given parameters")

// UnableToRecognizeInputType indicates that the loader could not recognize the input from stdin.
var UnableToRecognizeInputType = errors.New("Unable to recognize input type")

// FailedToProcessInput indicates that the loader failed to process a specific input.
type FailedToProcessInput struct {
	// The path that failed to process.
	Path string
	err  error
}

func (e *FailedToProcessInput) Error() string {
	return fmt.Sprintf("Failed to load input %s: %v", e.Path, e.err)
}

func (e *FailedToProcessInput) Unwrap() error {
	return e.err
}

// UnsupportedInputType indicates that a particular InputType is not supported by
// this package.
var UnsupportedInputType = errors.New("Unsupported input type")

// UnableToResolveLocation indicates that a detector could not resolve the location of
// the given resource / attribute path.
var UnableToResolveLocation = errors.New("Unable to resolve location")

/////////////////////
// Detector errors //
/////////////////////

// UnrecognizedFileExtension indicates that a detector was invoked on a file which does
// not have a recognized file extension.
var UnrecognizedFileExtension = errors.New("Unrecognized file extension")

// FailedToParseInput indicates that a detector failed to parse a specific input.
var FailedToParseInput = errors.New("Failed to parse input")

// InvalidInput indicates that an input does not match the expected format.
var InvalidInput = errors.New("Invalid input for input type")

//////////////////
// Input errors //
//////////////////

// UnableToReadFile indicates that a file could not be read.
var UnableToReadFile = errors.New("Unable to read file")

// UnableToReadDir indicates that a file could not be read.
var UnableToReadDir = errors.New("Unable to read directory")

// UnableToReadStdin indicates that a file could not be read.
var UnableToReadStdin = errors.New("Unable to read stdin")

package input

import (
	"errors"
)

/////////////////////
// Detector errors //
/////////////////////

// UnsupportedInputType indicates that a particular InputType is not supported by
// this package.
var UnsupportedInputType = errors.New("Unsupported input type")

///////////////////
// Loader errors //
///////////////////

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

///////////////////////
// Detectable errors //
///////////////////////

// UnableToReadFile indicates that a file could not be read.
var UnableToReadFile = errors.New("Unable to read file")

// UnableToReadDir indicates that a file could not be read.
var UnableToReadDir = errors.New("Unable to read directory")

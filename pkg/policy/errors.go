package policy

import (
	"errors"
)

// FailedToQueryMetadata indicates that an error occurred while querying the policy's
// metadata rule.
var FailedToQueryMetadata = errors.New("Failed to query metadata")

// FailedToPrepareForEval indicates that an error occurred while preparing the judgement
// rule query for the policy.
var FailedToPrepareForEval = errors.New("Failed to prepare for evaluation")

// FailedToEvaluateRule indicates that an error occurred while evaluating the judgement
// rule for the policy.
var FailedToEvaluateRule = errors.New("Failed to evaluate rule")

// FailedToEvaluateResource indicates that an error occurred while evaluating the
// judgement rule query for the policy for a particular resource.
var FailedToEvaluateResource = errors.New("Failed to evaluate rule for resource")

// FailedToQueryResources indicates that an error occurred while querying the policy's
// resources rule.
var FailedToQueryResources = errors.New("Failed to query resources")

// FailedToProcessResults indicates that an error occurred while processing the results
// of the judgement rule query.
var FailedToProcessResults = errors.New("Failed to process results")

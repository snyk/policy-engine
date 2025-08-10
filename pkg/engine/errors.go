// © 2022-2023 Snyk Limited All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package engine

import (
	"errors"
	"fmt"
	"time"
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

// ErrFailedToReadBundle indicates that an error occurred while consuming a
// bundle.Reader.
var ErrFailedToReadBundle = errors.New("failed to load bundle")

// ErrInitTimedOut indicates that initialization took too long and was cancelled.
type ErrInitTimedOut struct {
	Timeout time.Duration
}

func (e ErrInitTimedOut) Error() string {
	return fmt.Sprintf("initialization timed out after %s", e.Timeout.String())
}

// ErrEvalTimedOut indicates that evaluation took too long and was cancelled.
type ErrEvalTimedOut struct {
	Timeout time.Duration
}

func (e ErrEvalTimedOut) Error() string {
	return fmt.Sprintf("initialization timed out after %s", e.Timeout.String())
}

// ErrQueryTimedOut indicates that a query took too long and was cancelled.
type ErrQueryTimedOut struct {
	Timeout time.Duration
}

func (e ErrQueryTimedOut) Error() string {
	return fmt.Sprintf("query timed out after %s", e.Timeout.String())
}

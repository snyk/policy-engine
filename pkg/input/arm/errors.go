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

package arm

import "fmt"

type ErrorKind string

const (
	TokenizerError      ErrorKind = "TokenizerError"
	ParserError         ErrorKind = "ParserError"
	EvalError           ErrorKind = "EvalError"
	UnsupportedFunction ErrorKind = "UnsupportedFunction"
)

// We have this error type so that we can use its `kind` as a metric label in
// the future. Since callers in practice do not pass in a metrics collector
// currently, we do nothing with it yet.
type Error struct {
	underlying error
	expression string
	kind       ErrorKind
}

func (e Error) Kind() ErrorKind {
	return e.kind
}

func (e Error) Error() string {
	return fmt.Sprintf("error evaluating expression '%s': %s", e.expression, e.underlying.Error())
}

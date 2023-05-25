// © 2023 Snyk Limited All rights reserved.
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

package withtimeout

import (
	"context"
	"errors"
	"time"
)

var ErrTimedOut = errors.New("timed out")

func Do(
	ctx context.Context,
	timeout time.Duration,
	timeoutErr error,
	do func(context.Context) error,
) (err error) {
	if timeoutErr == nil {
		timeoutErr = ErrTimedOut
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	errChan := make(chan error)

	go func() {
		defer close(errChan)
		if err := do(ctx); err != nil {
			errChan <- err
		} else {
			errChan <- nil
		}
	}()

	select {
	case err = <-errChan:
		return
	case <-ctx.Done():
		err = timeoutErr
		return
	}
}

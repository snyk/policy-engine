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

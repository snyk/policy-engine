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

package logging

import (
	"context"
	"os"

	"github.com/rs/zerolog"
)

// StdErrLogger writes structured log messages to stderr
var StdErrLogger Logger = NewZeroLogger(zerolog.Logger{}.
	Level(zerolog.GlobalLevel()).
	Output(os.Stderr).
	With().Timestamp().Logger())

// NopLogger does not write any messages. It can be used to disable logging.
var NopLogger Logger = NewZeroLogger(zerolog.Nop())

// Logger defines a simple interface for the pluggable logging in the policy engine
type Logger interface {
	Trace(ctx context.Context, msg string)
	Debug(ctx context.Context, msg string)
	Info(ctx context.Context, msg string)
	Warn(ctx context.Context, msg string)
	Error(ctx context.Context, msg string)
	WithError(err error) Logger
	WithField(name string, value interface{}) Logger
}

// DefaultLogger is an implementation of the Logger interface that uses zerolog
// internally.
type ZeroLogger struct {
	zl zerolog.Logger
}

func NewZeroLogger(zl zerolog.Logger) Logger {
	return &ZeroLogger{
		zl: zl,
	}
}

func (l *ZeroLogger) Trace(_ context.Context, msg string) {
	l.zl.Trace().Msg(msg)
}
func (l *ZeroLogger) Debug(_ context.Context, msg string) {
	l.zl.Debug().Msg(msg)
}
func (l *ZeroLogger) Info(_ context.Context, msg string) {
	l.zl.Info().Msg(msg)
}
func (l *ZeroLogger) Warn(_ context.Context, msg string) {
	l.zl.Warn().Msg(msg)
}
func (l *ZeroLogger) Error(_ context.Context, msg string) {
	l.zl.Error().Msg(msg)
}
func (l *ZeroLogger) WithError(err error) Logger {
	return &ZeroLogger{
		zl: l.zl.With().Err(err).Logger(),
	}
}
func (l *ZeroLogger) WithField(name string, value interface{}) Logger {
	return &ZeroLogger{
		zl: l.zl.With().Fields(map[string]interface{}{
			name: value,
		}).Logger(),
	}
}

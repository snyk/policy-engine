package logging

import (
	"context"
	"os"

	"github.com/rs/zerolog"
)

var DefaultLogger Logger = NewZeroLogger(zerolog.Logger{}.
	Level(zerolog.GlobalLevel()).
	Output(os.Stderr).
	With().Timestamp().Logger())

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

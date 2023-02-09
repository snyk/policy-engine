package engine

import (
	"context"
	"fmt"
	"time"

	"github.com/snyk/policy-engine/pkg/logging"
	"github.com/snyk/policy-engine/pkg/metrics"
)

type level int

const (
	info = iota
	debug
	trace
)

type instrumentation struct {
	component       string
	labels          metrics.Labels
	logger          logging.Logger
	metrics         metrics.Metrics
	phaseStartTimes map[string]time.Time
	level           level
}

type instrumentationOptions struct {
	component string
	labels    metrics.Labels
	logger    logging.Logger
	metrics   metrics.Metrics
	level     level
}

func newInstrumentation(options instrumentationOptions) instrumentation {
	return instrumentation{
		component: options.component,
		labels: metrics.MergeLabels(options.labels, metrics.Labels{
			"component": options.component,
		}),
		logger:          options.logger.WithField("component", options.component),
		metrics:         options.metrics,
		phaseStartTimes: map[string]time.Time{},
		level:           options.level,
	}
}

type loggerOption func(l logging.Logger) logging.Logger

func withField(name string, val interface{}) loggerOption {
	return func(l logging.Logger) logging.Logger {
		return l.WithField(name, val)
	}
}

func (i *instrumentation) startPhase(ctx context.Context, phase string, opts ...loggerOption) {
	logger := i.logger.WithField("phase", phase)
	for _, opt := range opts {
		logger = opt(logger)
	}
	i.phaseStartTimes[phase] = time.Now()
	i.logFromLevel(ctx, logger, "phase started")
}

func (i *instrumentation) finishPhase(ctx context.Context, phase string, opts ...loggerOption) {
	duration := time.Since(i.phaseStartTimes[phase])
	logger := i.logger.
		WithField("phase", phase).
		WithField("duration_ms", duration.Milliseconds())
	for _, opt := range opts {
		logger = opt(logger)
	}
	i.logFromLevel(ctx, logger, "phase finished")
	i.metrics.
		Timer(ctx, fmt.Sprintf("%s_time", phase), "", i.labels).
		Record(duration)
}

func (i *instrumentation) child(labels metrics.Labels, level level, opts ...loggerOption) instrumentation {
	logger := i.logger
	for _, opt := range opts {
		logger = opt(logger)
	}
	return newInstrumentation(instrumentationOptions{
		component: i.component,
		metrics:   i.metrics,
		labels:    metrics.MergeLabels(i.labels, labels),
		logger:    logger,
		level:     level,
	})
}

func (i *instrumentation) logFromLevel(ctx context.Context, logger logging.Logger, msg string) {
	switch i.level {
	case info:
		logger.Info(ctx, msg)
	case debug:
		logger.Debug(ctx, msg)
	case trace:
		logger.Trace(ctx, msg)
	}
}

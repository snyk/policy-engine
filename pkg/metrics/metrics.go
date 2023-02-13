// Copyright 2022-2023 Snyk Ltd
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

package metrics

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/snyk/policy-engine/pkg/logging"
)

type Buckets []float64

type Labels = map[string]string

func MergeLabels(labels ...Labels) Labels {
	merged := Labels{}
	for _, l := range labels {
		for k, v := range l {
			merged[k] = v
		}
	}
	return merged
}

type Histogram interface {
	Observe(val float64)
}

type Counter interface {
	Inc()
	Add(val float64)
}

type Timer interface {
	Record(d time.Duration)
}

type Metrics interface {
	Counter(ctx context.Context, name, description string, labels Labels) Counter
	Timer(ctx context.Context, name, description string, labels Labels) Timer
}

type LocalCounter struct {
	name        string
	description string
	labels      Labels
	locker      sync.RWMutex
	count       float64
}

func NewLocalCounter(name, description string, labels Labels) Counter {
	return &LocalCounter{
		name:        name,
		description: description,
		labels:      labels,
		locker:      sync.RWMutex{},
		count:       0,
	}
}

func (l *LocalCounter) Inc() {
	l.locker.Lock()
	defer l.locker.Unlock()
	l.count++
}

func (l *LocalCounter) Add(val float64) {
	l.locker.Lock()
	defer l.locker.Unlock()
	l.count += val
}

func (l *LocalCounter) Count() float64 {
	l.locker.RLock()
	defer l.locker.RUnlock()
	return l.count
}

type LocalTimer struct {
	name        string
	description string
	labels      Labels
	locker      sync.RWMutex
	duration    time.Duration
}

func NewLocalTimer(name, description string, labels Labels) Timer {
	return &LocalTimer{
		name:        name,
		description: description,
		labels:      labels,
		locker:      sync.RWMutex{},
		duration:    0,
	}
}

func (l *LocalTimer) Record(d time.Duration) {
	l.locker.Lock()
	defer l.locker.Unlock()
	l.duration = d
}

func (l *LocalTimer) Duration() time.Duration {
	l.locker.RLock()
	defer l.locker.RUnlock()
	return l.duration
}

func calcKey(name string, labels Labels) string {
	// name + (key + value of each label)
	labelValues := make([]string, 0, len(labels)*2)
	for k, v := range labels {
		labelValues = append(labelValues, k+"_"+v)
	}
	sort.Strings(labelValues)
	return name + "_" + strings.Join(labelValues, "_")
}

type LocalMetrics struct {
	logger   logging.Logger
	counters *sync.Map
	timers   *sync.Map
}

func NewLocalMetrics(logger logging.Logger) *LocalMetrics {
	return &LocalMetrics{
		logger:   logger,
		counters: &sync.Map{},
		timers:   &sync.Map{},
	}
}

func (l *LocalMetrics) Counter(_ context.Context, name, description string, labels Labels) Counter {
	key := calcKey(name, labels)
	if value, found := l.counters.Load(key); found {
		return value.(Counter)
	}
	counter := NewLocalCounter(name, description, labels)
	l.counters.Store(key, counter)
	return counter
}

func (l *LocalMetrics) Timer(_ context.Context, name, description string, labels Labels) Timer {
	key := calcKey(name, labels)
	if value, found := l.timers.Load(key); found {
		return value.(Timer)
	}
	timer := NewLocalTimer(name, description, labels)
	l.timers.Store(key, timer)
	return timer
}

func (l *LocalMetrics) Log(ctx context.Context) {
	metrics := map[string][]map[string]interface{}{}
	l.counters.Range(func(_, value interface{}) bool {
		if counter, ok := value.(*LocalCounter); ok {
			m := map[string]interface{}{}
			m["type"] = "counter"
			m["labels"] = counter.labels
			m["count"] = counter.Count()
			metrics[counter.name] = append(metrics[counter.name], m)
		}
		return true
	})
	l.timers.Range(func(_, value interface{}) bool {
		if timer, ok := value.(*LocalTimer); ok {
			m := map[string]interface{}{}
			m["type"] = "timer"
			m["labels"] = timer.labels
			m["duration_ms"] = timer.Duration().Milliseconds()
			metrics[timer.name] = append(metrics[timer.name], m)
		}
		return true
	})
	l.logger.WithField("metrics", metrics).Debug(ctx, "Collected metrics")
}

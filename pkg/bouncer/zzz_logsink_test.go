package bouncer

import (
	"bytes"
	"log/slog"
	"sync"
)

// syncLogSink is a slog writer a test can read while the code under test still logs.
type syncLogSink struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

// Write appends one handler record under the same mutex String reads.
func (s *syncLogSink) Write(record []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(record)
}

// String is everything logged so far. Read this, never the buffer.
func (s *syncLogSink) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// newTestLogSink is a JSON logger at level plus the sink its output must be read through.
func newTestLogSink(level slog.Level) (*slog.Logger, *syncLogSink) {
	sink := &syncLogSink{}
	return slog.New(slog.NewJSONHandler(sink, &slog.HandlerOptions{Level: level})), sink
}

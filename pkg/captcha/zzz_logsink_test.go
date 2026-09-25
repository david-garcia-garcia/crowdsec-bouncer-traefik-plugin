package captcha

import (
	"bytes"
	"log/slog"
	"sync"
)

type syncLogSink struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncLogSink) Write(record []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(record)
}

func (s *syncLogSink) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

func newTestLogSink(level slog.Level) (*slog.Logger, *syncLogSink) {
	sink := &syncLogSink{}
	return slog.New(slog.NewJSONHandler(sink, &slog.HandlerOptions{Level: level})), sink
}

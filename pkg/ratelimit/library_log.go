package ratelimit

import (
	"context"
	"log/slog"
)

// debugCappedHandler writes every record of the wrapped handler at DEBUG at most.
// The simpleredis client logs WARN and ERROR per failed dial or command; under this leg one failing
// request is one DEBUG line, so the library lines it causes stay at DEBUG too. The outage itself is
// logged by the Client: MsgRedisUnavailable debounced, and the admission gate's backoff lines.
type debugCappedHandler struct {
	inner slog.Handler
}

// debugCappedLogger returns log with every record capped at DEBUG.
func debugCappedLogger(log *slog.Logger) *slog.Logger {
	return slog.New(debugCappedHandler{inner: log.Handler()})
}

// Enabled reports whether the wrapped handler writes level once it is capped at DEBUG.
func (handler debugCappedHandler) Enabled(ctx context.Context, level slog.Level) bool {
	if level > slog.LevelDebug {
		level = slog.LevelDebug
	}
	return handler.inner.Enabled(ctx, level)
}

// Handle writes record at DEBUG when its level is above DEBUG.
func (handler debugCappedHandler) Handle(ctx context.Context, record slog.Record) error {
	if record.Level > slog.LevelDebug {
		record.Level = slog.LevelDebug
	}
	return handler.inner.Handle(ctx, record)
}

// WithAttrs keeps the cap on the handler with attrs.
func (handler debugCappedHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return debugCappedHandler{inner: handler.inner.WithAttrs(attrs)}
}

// WithGroup keeps the cap on the handler with the group.
func (handler debugCappedHandler) WithGroup(name string) slog.Handler {
	return debugCappedHandler{inner: handler.inner.WithGroup(name)}
}

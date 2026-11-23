// Package logger builds the plugin's slog logger. It supports trace, debug, info, warn and error
// levels and writes to stdout; Traefik or the container runtime owns where those lines go next.
package logger

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
)

// output is where loggers built from now on write. It is stdout outside tests.
//
//nolint:gochecknoglobals // test-only redirect of a process-wide sink; guarded by outputMu
var (
	outputMu sync.Mutex
	output   io.Writer = os.Stdout
)

// Custom log levels following slog best practices.
// LevelTrace is below Debug (slog.Level(-8)), matching the Go slog custom-levels example.
const (
	LevelTrace = slog.Level(-8)
	LevelDebug = slog.LevelDebug
	LevelInfo  = slog.LevelInfo
	LevelWarn  = slog.LevelWarn
	LevelError = slog.LevelError
)

// Trace logs at LevelTrace. slog.Logger has no Trace method.
func Trace(log *slog.Logger, msg string, args ...any) {
	log.Log(context.Background(), LevelTrace, msg, args...)
}

// New creates a Log wrapper with default format (common).
func New(logLevel string) *slog.Logger {
	return NewWithFormat(logLevel, "common")
}

// NewWithFormat creates a Log wrapper with specified format (common or json).
func NewWithFormat(logLevel, logFormat string) *slog.Logger {
	// Determine log level
	var level slog.Level
	switch logLevel {
	case "ERROR":
		level = LevelError
	case "WARN":
		level = LevelWarn
	case "INFO":
		level = LevelInfo
	case "DEBUG":
		level = LevelDebug
	case "TRACE":
		level = LevelTrace
	default:
		// Default to INFO level
		level = LevelInfo
	}

	outputMu.Lock()
	writer := output
	outputMu.Unlock()

	// Create handler based on format with custom level names
	var handler slog.Handler
	opts := &slog.HandlerOptions{
		Level: level,
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			// Customize level names to match our expected format
			if a.Key == slog.LevelKey {
				lvl, ok := a.Value.Any().(slog.Level)
				if !ok {
					return a
				}
				switch {
				case lvl < LevelDebug:
					a.Value = slog.StringValue("TRACE")
				case lvl < LevelInfo:
					a.Value = slog.StringValue("DEBUG")
				case lvl < LevelWarn:
					a.Value = slog.StringValue("INFO")
				case lvl < LevelError:
					a.Value = slog.StringValue("WARN")
				default:
					a.Value = slog.StringValue("ERROR")
				}
			}
			return a
		},
	}

	if strings.EqualFold(logFormat, "json") {
		handler = slog.NewJSONHandler(writer, opts)
	} else {
		// Common format (default)
		handler = slog.NewTextHandler(writer, opts)
	}

	// Create logger with component attribute
	return slog.New(handler).With("component", "CrowdsecBouncer")
}

// SetOutputForTest makes loggers built after the call write to w instead of stdout, until the
// returned restore runs. Loggers built earlier keep their writer. Test-only.
func SetOutputForTest(w io.Writer) (restore func()) {
	outputMu.Lock()
	previous := output
	output = w
	outputMu.Unlock()
	return func() {
		outputMu.Lock()
		output = previous
		outputMu.Unlock()
	}
}

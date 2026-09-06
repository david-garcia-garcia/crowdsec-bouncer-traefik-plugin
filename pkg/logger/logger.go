// Package logger implements utility routines to write to stdout and stderr.
// It supports trace, debug, info, warn and error level using Go's standard log/slog
package logger

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// sharedLogFiles holds process-lifetime log files keyed by cleaned path.
//
//nolint:gochecknoglobals // intentional process-wide cache for Traefik reload semantics
var sharedLogFiles sync.Map

// Custom log levels following slog best practices.
const (
	LevelDebug = slog.LevelDebug
	LevelInfo  = slog.LevelInfo
	LevelWarn  = slog.LevelWarn
	LevelError = slog.LevelError
)

// New creates a Log wrapper with default format (common).
func New(logLevel string, logFilePath string) *slog.Logger {
	return NewWithFormat(logLevel, logFilePath, "common")
}

// NewWithFormat creates a Log wrapper with specified format (common or json).
func NewWithFormat(logLevel, logFilePath, logFormat string) *slog.Logger {
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
	default:
		// Default to INFO level
		level = LevelInfo
	}

	output := logOutput(logFilePath)

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
		handler = slog.NewJSONHandler(output, opts)
	} else {
		// Common format (default)
		handler = slog.NewTextHandler(output, opts)
	}

	// Create logger with component attribute
	return slog.New(handler).With("component", "CrowdsecBouncerTraefikPlugin")
}

// logOutput returns stdout or a process-lifetime shared file for logFilePath.
func logOutput(logFilePath string) *os.File {
	if logFilePath == "" {
		return os.Stdout
	}

	path := filepath.Clean(logFilePath)
	if existing, ok := sharedLogFiles.Load(path); ok {
		if file, isFile := existing.(*os.File); isFile {
			return file
		}
	}

	logFile, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		slog.Warn("LogFilePath is not writable, using stdout", "error", err)
		return os.Stdout
	}

	actual, loaded := sharedLogFiles.LoadOrStore(path, logFile)
	if loaded {
		_ = logFile.Close()
	}
	if file, ok := actual.(*os.File); ok {
		return file
	}
	return os.Stdout
}

// ResetSharedLogFilesForTest closes and clears process-lifetime log files. Test-only.
func ResetSharedLogFilesForTest() {
	sharedLogFiles.Range(func(key, value any) bool {
		if file, ok := value.(*os.File); ok {
			_ = file.Close()
		}
		sharedLogFiles.Delete(key)
		return true
	})
}

func sharedLogFileCountForTest() int {
	count := 0
	sharedLogFiles.Range(func(_, _ any) bool {
		count++
		return true
	})
	return count
}

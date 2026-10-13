package logger

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name     string
		logLevel string
	}{
		{name: "ERROR level", logLevel: "ERROR"},
		{name: "WARN level", logLevel: "WARN"},
		{name: "INFO level", logLevel: "INFO"},
		{name: "DEBUG level", logLevel: "DEBUG"},
		{name: "TRACE level", logLevel: "TRACE"},
		{name: "Default level (INFO)", logLevel: "INVALID"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := New(tt.logLevel, "")

			// Verify logger is created
			if logger == nil {
				t.Fatal("Expected logger to be created, got nil")
			}

			// Verify it's a slog.Logger (we can call methods on it)
			logger.Info("test initialization")
		})
	}
}

func TestNewWithFormatJSONCaseInsensitive(t *testing.T) {
	for _, format := range []string{"JSON", "json", "Json"} {
		t.Run(format, func(t *testing.T) {
			logPath := filepath.Join(t.TempDir(), "format.log")
			t.Cleanup(ResetSharedLogFilesForTest)
			logger := NewWithFormat("INFO", logPath, format)
			if logger == nil {
				t.Fatal("expected logger")
			}

			testMessage := "json format case test"
			logger.Info(testMessage)

			// #nosec G304 -- logPath is a test-generated temporary file path
			data, err := os.ReadFile(logPath)
			if err != nil {
				t.Fatalf("read log file: %v", err)
			}

			lines := strings.Split(strings.TrimSpace(string(data)), "\n")
			if len(lines) != 1 {
				t.Fatalf("expected 1 log line, got %d: %q", len(lines), string(data))
			}

			var logEntry map[string]interface{}
			if err := json.Unmarshal([]byte(lines[0]), &logEntry); err != nil {
				t.Fatalf("expected valid JSON, got %v output=%q", err, lines[0])
			}
			if logEntry["level"] != "INFO" {
				t.Errorf("expected level INFO, got %v", logEntry["level"])
			}
			if logEntry["msg"] != testMessage {
				t.Errorf("expected msg %q, got %v", testMessage, logEntry["msg"])
			}
			if logEntry["component"] != "CrowdsecBouncer" {
				t.Errorf("expected component, got %v", logEntry["component"])
			}
		})
	}
}

func TestSharedLogFilePerPath(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "shared.log")
	t.Cleanup(ResetSharedLogFilesForTest)

	_ = NewWithFormat("INFO", logPath, "common")
	_ = NewWithFormat("INFO", logPath, "common")
	_ = NewWithFormat("INFO", logPath, "json")

	if count := sharedLogFileCountForTest(); count != 1 {
		t.Fatalf("expected 1 shared log file, got %d", count)
	}
}

func TestInvalidLogFile(t *testing.T) {
	// Try to create logger with invalid file path
	logger := New("INFO", "/invalid/path/that/does/not/exist/test.log")

	// Logger should still be created (falls back to stdout)
	if logger == nil {
		t.Fatal("Expected logger to be created even with invalid file path")
	}

	// Should not panic when logging
	logger.Info("test message")
}

func TestTraceLevelNameAndFiltering(t *testing.T) {
	tracePath := filepath.Join(t.TempDir(), "trace.log")
	debugPath := filepath.Join(t.TempDir(), "debug.log")
	t.Cleanup(ResetSharedLogFilesForTest)

	traceLog := NewWithFormat("TRACE", tracePath, "json")
	Trace(traceLog, "hotpath")
	traceLog.Debug("startup")

	debugLog := NewWithFormat("DEBUG", debugPath, "json")
	Trace(debugLog, "hotpath")
	debugLog.Debug("startup")

	// #nosec G304 -- paths are test-generated temporary files
	traceData, err := os.ReadFile(tracePath)
	if err != nil {
		t.Fatalf("read TRACE log: %v", err)
	}
	traceOut := string(traceData)
	if !strings.Contains(traceOut, `"level":"TRACE"`) {
		t.Fatalf("TRACE logger should name LevelTrace as TRACE, got %s", traceOut)
	}
	if !strings.Contains(traceOut, `"msg":"hotpath"`) {
		t.Fatalf("TRACE logger should emit Trace, got %s", traceOut)
	}
	if !strings.Contains(traceOut, `"level":"DEBUG"`) || !strings.Contains(traceOut, `"msg":"startup"`) {
		t.Fatalf("TRACE logger should still emit Debug, got %s", traceOut)
	}

	// #nosec G304 -- paths are test-generated temporary files
	debugData, err := os.ReadFile(debugPath)
	if err != nil {
		t.Fatalf("read DEBUG log: %v", err)
	}
	debugOut := string(debugData)
	if strings.Contains(debugOut, `"msg":"hotpath"`) || strings.Contains(debugOut, `"level":"TRACE"`) {
		t.Fatalf("DEBUG logger should drop Trace, got %s", debugOut)
	}
	if !strings.Contains(debugOut, `"level":"DEBUG"`) || !strings.Contains(debugOut, `"msg":"startup"`) {
		t.Fatalf("DEBUG logger should emit Debug, got %s", debugOut)
	}
}

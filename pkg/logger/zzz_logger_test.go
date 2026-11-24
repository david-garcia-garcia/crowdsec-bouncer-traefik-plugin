package logger

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// captureOutput sends loggers built during the test to a buffer.
func captureOutput(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	t.Cleanup(SetOutputForTest(&buf))
	return &buf
}

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
			logger := New(tt.logLevel)

			// Verify logger is created
			if logger == nil {
				t.Fatal("Expected logger to be created, got nil")
			}

			// Verify it's a slog.Logger (we can call methods on it)
			logger.Info("test initialization")
		})
	}
}

// TestDefaultOutputIsStdout proves a logger built outside SetOutputForTest writes to stdout.
func TestDefaultOutputIsStdout(t *testing.T) {
	outputMu.Lock()
	writer := output
	outputMu.Unlock()
	if writer != os.Stdout {
		t.Fatalf("default output = %T, want os.Stdout", writer)
	}
}

// TestSetOutputForTestRestores proves restore puts the previous writer back for later loggers.
func TestSetOutputForTestRestores(t *testing.T) {
	var first, second bytes.Buffer
	restoreFirst := SetOutputForTest(&first)
	restoreSecond := SetOutputForTest(&second)
	New("INFO").Info("to second")
	restoreSecond()
	New("INFO").Info("to first")
	restoreFirst()

	if !strings.Contains(second.String(), "to second") || strings.Contains(second.String(), "to first") {
		t.Fatalf("second buffer = %q", second.String())
	}
	if !strings.Contains(first.String(), "to first") || strings.Contains(first.String(), "to second") {
		t.Fatalf("first buffer = %q", first.String())
	}
}

func TestNewWithFormatJSONCaseInsensitive(t *testing.T) {
	for _, format := range []string{"JSON", "json", "Json"} {
		t.Run(format, func(t *testing.T) {
			buf := captureOutput(t)
			logger := NewWithFormat("INFO", format)
			if logger == nil {
				t.Fatal("expected logger")
			}

			testMessage := "json format case test"
			logger.Info(testMessage)

			lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
			if len(lines) != 1 {
				t.Fatalf("expected 1 log line, got %d: %q", len(lines), buf.String())
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

func TestTraceLevelNameAndFiltering(t *testing.T) {
	traceBuf := captureOutput(t)
	traceLog := NewWithFormat("TRACE", "json")
	Trace(traceLog, "hotpath")
	traceLog.Debug("startup")

	debugBuf := captureOutput(t)
	debugLog := NewWithFormat("DEBUG", "json")
	Trace(debugLog, "hotpath")
	debugLog.Debug("startup")

	traceOut := traceBuf.String()
	if !strings.Contains(traceOut, `"level":"TRACE"`) {
		t.Fatalf("TRACE logger should name LevelTrace as TRACE, got %s", traceOut)
	}
	if !strings.Contains(traceOut, `"msg":"hotpath"`) {
		t.Fatalf("TRACE logger should emit Trace, got %s", traceOut)
	}
	if !strings.Contains(traceOut, `"level":"DEBUG"`) || !strings.Contains(traceOut, `"msg":"startup"`) {
		t.Fatalf("TRACE logger should still emit Debug, got %s", traceOut)
	}

	debugOut := debugBuf.String()
	if strings.Contains(debugOut, `"msg":"hotpath"`) || strings.Contains(debugOut, `"level":"TRACE"`) {
		t.Fatalf("DEBUG logger should drop Trace, got %s", debugOut)
	}
	if !strings.Contains(debugOut, `"level":"DEBUG"`) || !strings.Contains(debugOut, `"msg":"startup"`) {
		t.Fatalf("DEBUG logger should emit Debug, got %s", debugOut)
	}
}

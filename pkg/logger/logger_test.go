package logger

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestNew_LogLevels(t *testing.T) {
	tests := []struct {
		name           string
		logLevel       string
		expectedLevels []string // levels that should be enabled
	}{
		{
			name:           "ERROR level",
			logLevel:       "ERROR",
			expectedLevels: []string{"ERROR"},
		},
		{
			name:           "WARN level",
			logLevel:       "WARN",
			expectedLevels: []string{"ERROR", "WARN"},
		},
		{
			name:           "INFO level",
			logLevel:       "INFO",
			expectedLevels: []string{"ERROR", "WARN", "INFO"},
		},
		{
			name:           "DEBUG level",
			logLevel:       "DEBUG",
			expectedLevels: []string{"ERROR", "WARN", "INFO", "DEBUG"},
		},
		{
			name:           "TRACE level",
			logLevel:       "TRACE",
			expectedLevels: []string{"ERROR", "WARN", "INFO", "DEBUG", "TRACE"},
		},
		{
			name:           "Default level (empty string)",
			logLevel:       "",
			expectedLevels: []string{"ERROR", "WARN", "INFO"},
		},
		{
			name:           "Invalid level",
			logLevel:       "INVALID",
			expectedLevels: []string{"ERROR", "WARN", "INFO"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := New(tt.logLevel, "")

			// Check which loggers are enabled by checking if their output is not io.Discard
			loggers := map[string]interface{}{
				"ERROR": logger.logError.Writer(),
				"WARN":  logger.logWarn.Writer(),
				"INFO":  logger.logInfo.Writer(),
				"DEBUG": logger.logDebug.Writer(),
				"TRACE": logger.logTrace.Writer(),
			}

			for level, writer := range loggers {
				isEnabled := writer != io.Discard
				shouldBeEnabled := false

				for _, expectedLevel := range tt.expectedLevels {
					if level == expectedLevel {
						shouldBeEnabled = true
						break
					}
				}

				if shouldBeEnabled && !isEnabled {
					t.Errorf("Expected %s level to be enabled, but it's writing to io.Discard", level)
				}
				if !shouldBeEnabled && isEnabled {
					t.Errorf("Expected %s level to be disabled, but it's not writing to io.Discard", level)
				}
			}
		})
	}
}

func TestNew_WithLogFile(t *testing.T) {
	// Create a unique temporary file name
	logFile := filepath.Join(os.TempDir(), "crowdsec_logger_test_"+strconv.FormatInt(time.Now().UnixNano(), 10)+".log")

	// Ensure cleanup
	defer func() {
		_ = os.Remove(logFile)
	}()

	logger := New("INFO", logFile)

	// Test that the logger was created successfully
	if logger == nil {
		t.Fatal("Expected logger to be created, got nil")
	}

	// Test logging to file
	logger.Info("test log message")
	logger.Error("test error message")

	// Give a moment for the file to be written
	time.Sleep(50 * time.Millisecond)

	// Read the file and verify content
	content, err := os.ReadFile(logFile) //nolint:gosec // G304: This is a test file with controlled path
	if err != nil {
		t.Fatalf("Failed to read log file: %v", err)
	}

	logContent := string(content)
	if !strings.Contains(logContent, "test log message") {
		t.Error("Expected log message not found in file")
	}
	if !strings.Contains(logContent, "test error message") {
		t.Error("Expected error message not found in file")
	}
}

func TestNew_InvalidLogFile(t *testing.T) {
	// Try to create logger with invalid log file path
	invalidPath := "/invalid/path/that/does/not/exist/test.log"

	// This should not panic and should fall back to stdout/stderr
	logger := New("INFO", invalidPath)
	if logger == nil {
		t.Fatal("Expected logger to be created even with invalid path, got nil")
	}

	// The logger should still work (writing to stdout/stderr)
	logger.Info("test message")
}

func TestLoggerMethods(t *testing.T) {
	var buf bytes.Buffer
	var errBuf bytes.Buffer

	logger := New("TRACE", "")

	// Replace outputs with our buffers
	logger.logError.SetOutput(&errBuf)
	logger.logWarn.SetOutput(&buf)
	logger.logInfo.SetOutput(&buf)
	logger.logDebug.SetOutput(&buf)
	logger.logTrace.SetOutput(&buf)

	// Test each method
	testMessage := "test message"

	logger.Trace(testMessage)
	logger.Debug(testMessage)
	logger.Info(testMessage)
	logger.Warn(testMessage)
	logger.Error(testMessage)

	// Verify all messages were logged
	output := buf.String()
	errorOutput := errBuf.String()
	allOutput := output + errorOutput

	expectedPrefixes := []string{"TRACE:", "DEBUG:", "INFO:", "WARN:", "ERROR:"}
	for _, prefix := range expectedPrefixes {
		if !strings.Contains(allOutput, prefix) {
			t.Errorf("Expected to find '%s' prefix in output", prefix)
		}
	}

	// Verify the test message appears for each level
	messageCount := strings.Count(allOutput, testMessage)
	if messageCount != 5 {
		t.Errorf("Expected test message to appear 5 times, got %d", messageCount)
	}
}

func TestLoggerOutput_ErrorGoesToStderr(t *testing.T) {
	// Create buffers to capture output
	var stdoutBuf bytes.Buffer
	var stderrBuf bytes.Buffer

	logger := New("TRACE", "")

	// Set outputs - errors should go to stderr, others to stdout
	logger.logError.SetOutput(&stderrBuf)
	logger.logWarn.SetOutput(&stdoutBuf)
	logger.logInfo.SetOutput(&stdoutBuf)
	logger.logDebug.SetOutput(&stdoutBuf)
	logger.logTrace.SetOutput(&stdoutBuf)

	logger.Error("error message")
	logger.Info("info message")

	// Verify error goes to stderr
	if !strings.Contains(stderrBuf.String(), "error message") {
		t.Error("Expected error message to go to stderr")
	}

	// Verify info goes to stdout
	if !strings.Contains(stdoutBuf.String(), "info message") {
		t.Error("Expected info message to go to stdout")
	}

	// Verify error doesn't go to stdout
	if strings.Contains(stdoutBuf.String(), "error message") {
		t.Error("Error message should not go to stdout")
	}

	// Verify info doesn't go to stderr
	if strings.Contains(stderrBuf.String(), "info message") {
		t.Error("Info message should not go to stderr")
	}
}

func TestLoggerTimestamp(t *testing.T) {
	var buf bytes.Buffer

	logger := New("INFO", "")
	logger.logInfo.SetOutput(&buf)

	logger.Info("test message with timestamp")

	output := buf.String()

	// Check that the output contains date and time
	// The log format includes Ldate|Ltime which should produce something like "2023/01/01 12:00:00"
	if !strings.Contains(output, "/") || !strings.Contains(output, ":") {
		t.Error("Expected timestamp to be present in log output")
	}

	// Check that the prefix is present
	if !strings.Contains(output, "INFO: CrowdsecBouncerTraefikPlugin:") {
		t.Error("Expected INFO prefix to be present in log output")
	}

	// Check that the message is present
	if !strings.Contains(output, "test message with timestamp") {
		t.Error("Expected log message to be present in output")
	}
}

func TestLogLevelHierarchy(t *testing.T) {
	// Test that the hierarchy is respected: TRACE > DEBUG > INFO > WARN > ERROR
	testCases := []struct {
		setLevel    string
		testLevel   string
		shouldLog   bool
		description string
	}{
		// ERROR level tests
		{"ERROR", "ERROR", true, "ERROR level should log ERROR"},
		{"ERROR", "WARN", false, "ERROR level should not log WARN"},
		{"ERROR", "INFO", false, "ERROR level should not log INFO"},
		{"ERROR", "DEBUG", false, "ERROR level should not log DEBUG"},
		{"ERROR", "TRACE", false, "ERROR level should not log TRACE"},

		// WARN level tests
		{"WARN", "ERROR", true, "WARN level should log ERROR"},
		{"WARN", "WARN", true, "WARN level should log WARN"},
		{"WARN", "INFO", false, "WARN level should not log INFO"},
		{"WARN", "DEBUG", false, "WARN level should not log DEBUG"},
		{"WARN", "TRACE", false, "WARN level should not log TRACE"},

		// INFO level tests
		{"INFO", "ERROR", true, "INFO level should log ERROR"},
		{"INFO", "WARN", true, "INFO level should log WARN"},
		{"INFO", "INFO", true, "INFO level should log INFO"},
		{"INFO", "DEBUG", false, "INFO level should not log DEBUG"},
		{"INFO", "TRACE", false, "INFO level should not log TRACE"},

		// DEBUG level tests
		{"DEBUG", "ERROR", true, "DEBUG level should log ERROR"},
		{"DEBUG", "WARN", true, "DEBUG level should log WARN"},
		{"DEBUG", "INFO", true, "DEBUG level should log INFO"},
		{"DEBUG", "DEBUG", true, "DEBUG level should log DEBUG"},
		{"DEBUG", "TRACE", false, "DEBUG level should not log TRACE"},

		// TRACE level tests
		{"TRACE", "ERROR", true, "TRACE level should log ERROR"},
		{"TRACE", "WARN", true, "TRACE level should log WARN"},
		{"TRACE", "INFO", true, "TRACE level should log INFO"},
		{"TRACE", "DEBUG", true, "TRACE level should log DEBUG"},
		{"TRACE", "TRACE", true, "TRACE level should log TRACE"},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			logger := New(tc.setLevel, "")

			// Check if the logger for this level is enabled by checking its writer
			var isEnabled bool
			switch tc.testLevel {
			case "ERROR":
				isEnabled = logger.logError.Writer() != io.Discard
			case "WARN":
				isEnabled = logger.logWarn.Writer() != io.Discard
			case "INFO":
				isEnabled = logger.logInfo.Writer() != io.Discard
			case "DEBUG":
				isEnabled = logger.logDebug.Writer() != io.Discard
			case "TRACE":
				isEnabled = logger.logTrace.Writer() != io.Discard
			}

			if tc.shouldLog && !isEnabled {
				t.Errorf("Expected message to be logged but logger is disabled")
			}
			if !tc.shouldLog && isEnabled {
				t.Errorf("Expected message not to be logged but logger is enabled")
			}
		})
	}
}

func TestLoggerFunctionality(t *testing.T) {
	// Test actual logging functionality
	var buf bytes.Buffer
	var errBuf bytes.Buffer

	logger := New("DEBUG", "")

	// Set outputs to capture logs
	logger.logError.SetOutput(&errBuf)
	logger.logWarn.SetOutput(&buf)
	logger.logInfo.SetOutput(&buf)
	logger.logDebug.SetOutput(&buf)
	// logTrace should remain disabled for DEBUG level

	// Test logging
	logger.Trace("trace message") // Should not appear
	logger.Debug("debug message") // Should appear
	logger.Info("info message")   // Should appear
	logger.Warn("warn message")   // Should appear
	logger.Error("error message") // Should appear

	allOutput := buf.String() + errBuf.String()

	// Check that enabled levels appear
	if !strings.Contains(allOutput, "debug message") {
		t.Error("Expected debug message to be logged")
	}
	if !strings.Contains(allOutput, "info message") {
		t.Error("Expected info message to be logged")
	}
	if !strings.Contains(allOutput, "warn message") {
		t.Error("Expected warn message to be logged")
	}
	if !strings.Contains(allOutput, "error message") {
		t.Error("Expected error message to be logged")
	}

	// Check that disabled level does not appear
	if strings.Contains(allOutput, "trace message") {
		t.Error("Expected trace message NOT to be logged at DEBUG level")
	}
}

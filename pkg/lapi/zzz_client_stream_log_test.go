package lapi

import (
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

// newTestStreamTickClient builds a stream Client that can poll a mock LAPI without starting tickers.
func newTestStreamTickClient(t *testing.T, log *slog.Logger, host string, httpClient *http.Client) *Client {
	t.Helper()
	client, _ := NewTestClient(log)
	client.crowdsecScheme = "http"
	client.crowdsecHost = host
	client.crowdsecPath = "/"
	client.crowdsecStreamRoute = crowdsecLapiStreamRoute
	client.updateInterval = 60
	client.pluginVersion = "test"
	client.sessionKey = "lapi:test-stream"
	client.isCrowdsecStreamStartup = 1
	attachTestTransport(client, httpClient, "test-key")
	return client
}

// captureTestStreamTickLog runs fn with a JSON slog handler at level and returns what it logged.
func captureTestStreamTickLog(t *testing.T, level slog.Level, fn func(*slog.Logger)) string {
	t.Helper()
	log, sink := newTestLogSink(level)
	fn(log)
	return sink.String()
}

// TestHandleStreamCacheUpdatedIsDebug proves a successful LAPI fetch logs at DEBUG, not INFO.
func TestHandleStreamCacheUpdatedIsDebug(t *testing.T) {
	server, _ := testStreamLAPI(t)
	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	const tickMsg = "handleStreamCache:updated"
	for _, tc := range []struct {
		level slog.Level
		want  bool
	}{
		{slog.LevelInfo, false},
		{slog.LevelDebug, true},
	} {
		t.Run(tc.level.String(), func(t *testing.T) {
			logged := captureTestStreamTickLog(t, tc.level, func(log *slog.Logger) {
				client := newTestStreamTickClient(t, log, serverURL.Host, server.Client())
				if err := client.handleStreamCache(); err != nil {
					t.Fatalf("handleStreamCache: %v", err)
				}
			})
			if got := strings.Contains(logged, tickMsg); got != tc.want {
				t.Fatalf("%s at %s: got %v want %v\n%s", tickMsg, tc.level, got, tc.want, logged)
			}
			if tc.want && !strings.Contains(logged, `"sessionKey":"lapi:test-stream"`) {
				t.Fatalf("updated at DEBUG missing sessionKey:\n%s", logged)
			}
		})
	}
}

// TestHandleStreamTickerPollLogsAreDebug proves enter and finish stems stay DEBUG and carry join fields.
func TestHandleStreamTickerPollLogsAreDebug(t *testing.T) {
	server, _ := testStreamLAPI(t)
	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		level slog.Level
		want  bool
	}{
		{slog.LevelInfo, false},
		{slog.LevelDebug, true},
	} {
		t.Run(tc.level.String(), func(t *testing.T) {
			logged := captureTestStreamTickLog(t, tc.level, func(log *slog.Logger) {
				client := newTestStreamTickClient(t, log, serverURL.Host, server.Client())
				client.handleStreamTicker()
			})
			for _, msg := range []string{"handleStreamTicker:poll", "handleStreamCache:updated"} {
				if got := strings.Contains(logged, msg); got != tc.want {
					t.Fatalf("%s at %s: got %v want %v\n%s", msg, tc.level, got, tc.want, logged)
				}
			}
			if tc.want {
				for _, field := range []string{
					`"sessionKey":"lapi:test-stream"`,
					`"startup":true`,
					`"new":0`,
					`"deleted":0`,
					`"fetches":1`,
				} {
					if !strings.Contains(logged, field) {
						t.Fatalf("poll at DEBUG missing %s:\n%s", field, logged)
					}
				}
			}
		})
	}
}

// TestHandleStreamTickerSkipLogsAreDebug proves a busy tick logs skip at DEBUG and does not GET.
func TestHandleStreamTickerSkipLogsAreDebug(t *testing.T) {
	server, hits := testStreamLAPI(t)
	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		level slog.Level
		want  bool
	}{
		{slog.LevelInfo, false},
		{slog.LevelDebug, true},
	} {
		t.Run(tc.level.String(), func(t *testing.T) {
			logged := captureTestStreamTickLog(t, tc.level, func(log *slog.Logger) {
				client := newTestStreamTickClient(t, log, serverURL.Host, server.Client())
				client.streamPollInFlight = 1
				client.handleStreamTicker()
			})
			const skipMsg = "handleStreamTicker:skip"
			if got := strings.Contains(logged, skipMsg); got != tc.want {
				t.Fatalf("%s at %s: got %v want %v\n%s", skipMsg, tc.level, got, tc.want, logged)
			}
			if strings.Contains(logged, "handleStreamTicker:poll") || strings.Contains(logged, "handleStreamCache:updated") {
				t.Fatalf("busy tick must not poll:\n%s", logged)
			}
			if got := atomic.LoadInt64(hits); got != 0 {
				t.Fatalf("LAPI hits=%d, want 0 on skip", got)
			}
		})
	}
}

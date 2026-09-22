package lapi

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
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
	client.instanceName = "shared"
	client.middlewareName = "test-mw"
	client.log = log.With(
		"traefikName", "test-mw",
		"instanceName", "shared",
		"leg", "lapi",
		"sessionKey", "lapi:test-stream",
	)
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

// testStreamLAPISequence serves one stream payload per GET, in order.
func testStreamLAPISequence(t *testing.T, payloads []Stream) *httptest.Server {
	t.Helper()
	var hits int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if !strings.Contains(req.URL.Path, "stream") {
			w.WriteHeader(http.StatusOK)
			return
		}
		idx := int(atomic.AddInt64(&hits, 1) - 1)
		payload := Stream{}
		if idx < len(payloads) {
			payload = payloads[idx]
		}
		_ = json.NewEncoder(w).Encode(payload)
	}))
	t.Cleanup(server.Close)
	return server
}

func testBan(value string) Decision {
	return Decision{Type: "ban", Scope: "Ip", Value: value, Duration: "1h", Origin: "crowdsec"}
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
			if tc.want && !strings.Contains(logged, `"startup":true`) {
				t.Fatalf("first apply missing startup=true:\n%s", logged)
			}
		})
	}
}

// TestHandleStreamTickerPollLogsAreDebug proves enter and finish stems stay DEBUG with startup=true.
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
					`"traefikName":"test-mw"`,
					`"instanceName":"shared"`,
					`"leg":"lapi"`,
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

// TestHandleStreamTickerSubsequentPollLogsDelta proves later polls set startup=false and log applied counts.
func TestHandleStreamTickerSubsequentPollLogsDelta(t *testing.T) {
	server := testStreamLAPISequence(t, []Stream{
		{New: []Decision{testBan("203.0.113.10"), testBan("203.0.113.11"), {Type: "log", Scope: "Ip", Value: "203.0.113.12", Duration: "1h"}}, Deleted: []Decision{testBan("198.51.100.1")}},
		{New: []Decision{testBan("203.0.113.13")}, Deleted: []Decision{testBan("203.0.113.10")}},
	})
	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	log, sink := newTestLogSink(slog.LevelDebug)
	client := newTestStreamTickClient(t, log, serverURL.Host, server.Client())
	client.handleStreamTicker()
	client.handleStreamTicker()
	logged := sink.String()

	if strings.Count(logged, `"msg":"handleStreamTicker:poll"`) != 2 {
		t.Fatalf("want 2 poll enter lines:\n%s", logged)
	}
	if strings.Count(logged, `"msg":"handleStreamCache:updated"`) != 2 {
		t.Fatalf("want 2 updated lines:\n%s", logged)
	}
	if !strings.Contains(logged, `"new":2`) || !strings.Contains(logged, `"deleted":1`) {
		t.Fatalf("startup apply must count written decisions (2 new, skip unknown, 1 deleted):\n%s", logged)
	}
	if !strings.Contains(logged, `"new":1`) {
		t.Fatalf("delta apply missing new=1:\n%s", logged)
	}
	startupTrue := strings.Count(logged, `"startup":true`)
	startupFalse := strings.Count(logged, `"startup":false`)
	if startupTrue < 2 || startupFalse < 2 {
		t.Fatalf("want startup=true on first enter+finish and startup=false on second, true=%d false=%d\n%s", startupTrue, startupFalse, logged)
	}
}

// TestHandleStreamTickerSkipLogsAreWarn proves a busy tick warns at default INFO and does not GET.
func TestHandleStreamTickerSkipLogsAreWarn(t *testing.T) {
	server, hits := testStreamLAPI(t)
	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	for _, level := range []slog.Level{slog.LevelInfo, slog.LevelDebug} {
		t.Run(level.String(), func(t *testing.T) {
			logged := captureTestStreamTickLog(t, level, func(log *slog.Logger) {
				client := newTestStreamTickClient(t, log, serverURL.Host, server.Client())
				if !client.decisionStore.TryBeginStreamPoll() {
					t.Fatal("store poll CAS")
				}
				client.handleStreamTicker()
			})
			if !strings.Contains(logged, "handleStreamTicker:skip") {
				t.Fatalf("skip missing at %s:\n%s", level, logged)
			}
			if !strings.Contains(logged, `"level":"WARN"`) {
				t.Fatalf("skip must be WARN at %s:\n%s", level, logged)
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

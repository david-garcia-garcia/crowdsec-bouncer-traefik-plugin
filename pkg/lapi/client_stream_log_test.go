package lapi

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"testing"

	cache "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
)

// newTestStreamTickClient builds a stream Client that can poll a mock LAPI without starting tickers.
func newTestStreamTickClient(t *testing.T, log *slog.Logger, host string, httpClient *http.Client) *Client {
	t.Helper()
	cacheClient := &cache.Client{}
	cacheClient.New(log, false, "", nil, "", "", "")
	return &Client{
		cacheClient:             cacheClient,
		log:                     log,
		crowdsecScheme:          "http",
		crowdsecHost:            host,
		crowdsecPath:            "/",
		crowdsecStreamRoute:     crowdsecLapiStreamRoute,
		crowdsecHeader:          crowdsecLapiHeader,
		crowdsecKey:             "test-key",
		updateInterval:          60,
		httpClient:              httpClient,
		pluginVersion:           "test",
		isCrowdsecStreamStartup: true,
	}
}

// captureTestStreamTickLog runs fn with a JSON slog handler at level and returns the buffer.
func captureTestStreamTickLog(t *testing.T, level slog.Level, fn func(*slog.Logger)) string {
	t.Helper()
	var buf bytes.Buffer
	fn(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: level})))
	return buf.String()
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
		})
	}
}

// TestHandleStreamCacheAlreadyUpdatedIsDebug proves a lease hit logs at DEBUG, not INFO.
func TestHandleStreamCacheAlreadyUpdatedIsDebug(t *testing.T) {
	const tickMsg = "handleStreamCache:alreadyUpdated"
	for _, tc := range []struct {
		level slog.Level
		want  bool
	}{
		{slog.LevelInfo, false},
		{slog.LevelDebug, true},
	} {
		t.Run(tc.level.String(), func(t *testing.T) {
			logged := captureTestStreamTickLog(t, tc.level, func(log *slog.Logger) {
				client := newTestStreamTickClient(t, log, "unused", nil)
				client.cacheClient.Set(cacheTimeoutKey, cache.NoBannedValue, 60)
				if err := client.handleStreamCache(); err != nil {
					t.Fatalf("handleStreamCache: %v", err)
				}
			})
			if got := strings.Contains(logged, tickMsg); got != tc.want {
				t.Fatalf("%s at %s: got %v want %v\n%s", tickMsg, tc.level, got, tc.want, logged)
			}
		})
	}
}

package bouncer

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	configuration "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
)

func TestNew_banTemplateUnavailableWarnsAndServesEmptyBody(t *testing.T) {
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	t.Run("empty ban path", func(t *testing.T) {
		log, sink := newTestLogSink(slog.LevelWarn)
		cfg := configuration.New()
		cfg.BouncerBanFilePath = ""
		b, err := New(next, "test", cfg, false, false, false, log)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		logged := sink.String()
		if strings.Count(logged, msgBanTemplateUnavailable) != 1 {
			t.Fatalf("want one ban template WARN, got %s", logged)
		}
		if !strings.Contains(logged, `"reason":"empty"`) {
			t.Fatalf("want reason empty, got %s", logged)
		}
		rw := httptest.NewRecorder()
		b.handleBanServeHTTP(rw, testClientRequest(httptest.NewRequest(http.MethodGet, "http://example.com/", nil), "192.0.2.1"), "TEST", headerReasonLAPI, "")
		if rw.Code != http.StatusForbidden {
			t.Fatalf("status = %d", rw.Code)
		}
		if rw.Body.Len() != 0 {
			t.Fatalf("want empty ban body, got %q", rw.Body.String())
		}
	})
	t.Run("unloadable ban path", func(t *testing.T) {
		log, sink := newTestLogSink(slog.LevelWarn)
		cfg := configuration.New()
		cfg.BouncerBanFilePath = filepath.Join(t.TempDir(), "missing-ban.html")
		b, err := New(next, "test", cfg, false, false, false, log)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		logged := sink.String()
		if strings.Count(logged, msgBanTemplateUnavailable) != 1 {
			t.Fatalf("want one ban template WARN, got %s", logged)
		}
		if !strings.Contains(logged, `"reason":"unloadable"`) {
			t.Fatalf("want reason unloadable, got %s", logged)
		}
		rw := httptest.NewRecorder()
		b.handleBanServeHTTP(rw, testClientRequest(httptest.NewRequest(http.MethodGet, "http://example.com/", nil), "192.0.2.1"), "TEST", headerReasonLAPI, "")
		if rw.Code != http.StatusForbidden {
			t.Fatalf("status = %d", rw.Code)
		}
		if rw.Body.Len() != 0 {
			t.Fatalf("want empty ban body, got %q", rw.Body.String())
		}
	})
}

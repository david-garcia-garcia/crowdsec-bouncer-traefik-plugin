package crowdsec_bouncer_traefik_plugin //nolint:revive,stylecheck

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/lapi"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/reclaim"
)

// TestServeHTTP_ZonedIPv6RemoteAddr covers upstream issue #411 / PR #412 end to end:
// a direct client on a link-local address with a zone (RemoteAddr "[fe80::1%eth0]:1234")
// must not get a technical error, LAPI must be asked for the address without the zone,
// and the cached decision must be keyed without the zone too.
func TestServeHTTP_ZonedIPv6RemoteAddr(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })

	var mu sync.Mutex
	var queried []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "decisions") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		ip := r.URL.Query().Get("ip")
		if ip == "" {
			_, _ = w.Write([]byte("null"))
			return
		}
		mu.Lock()
		queried = append(queried, ip)
		mu.Unlock()
		if ip == "fe80::1" {
			_ = json.NewEncoder(w).Encode([]lapi.Decision{{Value: ip, Type: "ban", Duration: "1h", Scope: "ip"}})
			return
		}
		_, _ = w.Write([]byte("null"))
	}))
	t.Cleanup(func() { srv.Close() })
	parsed, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	cfg := cfgLiveAt(parsed.Host)
	cfg.LogLevel = "ERROR"
	cfg.LapiDefaultDecisionSeconds = 60
	cfg.BouncerRemediationHeadersCustomName = "X-Remediation"
	handler, err := New(context.Background(), testNextOK(), cfg, "zoned-ipv6")
	if err != nil {
		t.Fatal(err)
	}

	serve := func(remoteAddr string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "http://example.com/foo", nil)
		req.RemoteAddr = remoteAddr
		rw := httptest.NewRecorder()
		handler.ServeHTTP(rw, req)
		return rw
	}
	queriedSnapshot := func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), queried...)
	}

	banned := serve("[fe80::1%eth0]:1234")
	if banned.Code != http.StatusForbidden {
		t.Fatalf("banned zoned client status=%d body=%q, want 403", banned.Code, banned.Body.String())
	}
	if got := banned.Header().Get("X-Remediation"); !strings.HasPrefix(got, "ban:lapi") {
		t.Fatalf("banned zoned client X-Remediation=%q, want a LAPI ban", got)
	}
	if got := queriedSnapshot(); len(got) != 1 || got[0] != "fe80::1" {
		t.Fatalf("LAPI queried with %q, want [fe80::1] (no zone)", got)
	}

	// Same address on another interface: the memo is keyed without the zone, so no new query.
	again := serve("[fe80::1%eth1]:4321")
	if again.Code != http.StatusForbidden {
		t.Fatalf("cached zoned client status=%d, want 403", again.Code)
	}
	if got := queriedSnapshot(); len(got) != 1 {
		t.Fatalf("LAPI queried %q, want the cached ban to answer the second zone", got)
	}

	clean := serve("[fe80::2%eth0]:1234")
	if clean.Code != http.StatusOK || clean.Body.String() != "OK" {
		t.Fatalf("clean zoned client status=%d body=%q, want origin OK", clean.Code, clean.Body.String())
	}
	if got := queriedSnapshot(); len(got) != 2 || got[1] != "fe80::2" {
		t.Fatalf("LAPI queried with %q, want fe80::2 (no zone) second", got)
	}
}

package crowdsec_bouncer_traefik_plugin //nolint:revive,stylecheck

import (
	"context"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/reclaim"
)

// TestNew_RejectsBackendBackoffFailureRatio stops at ValidateParams so New does not open LAPI.
func TestNew_RejectsBackendBackoffFailureRatio(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })

	var hits int64
	srv := liveLAPI(t, nil, &hits)
	t.Cleanup(func() { srv.Close() })
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	cfg := cfgLiveAt(u.Host)
	cfg.BackendBackoffFailureRatio = 1.5

	handler, err := New(context.Background(), testNextOK(), cfg, "bad-backoff")
	if err == nil {
		t.Fatal("New must fail when backendBackoffFailureRatio is 1.5")
	}
	if handler != nil {
		t.Fatal("New must return a nil handler when backoff knobs are invalid")
	}
	if atomic.LoadInt64(&hits) != 0 {
		t.Fatalf("New opened LAPI (%d hits)", hits)
	}
}

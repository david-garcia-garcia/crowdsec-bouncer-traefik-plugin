package crowdsec_bouncer_traefik_plugin //nolint:revive,stylecheck

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/lapi"
	"github.com/david-garcia-garcia/traefik-middleware-utilities/traefikemulator"
)

// throttleLiveLAPI answers every live ip= query with one throttle decision for that IP.
func throttleLiveLAPI(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "decisions") {
			w.WriteHeader(http.StatusOK)
			return
		}
		_ = json.NewEncoder(w).Encode([]lapi.Decision{{
			Value:    r.URL.Query().Get("ip"),
			Type:     "throttle",
			Scope:    "Ip",
			Origin:   "cscli",
			Duration: "1h",
		}})
	}))
	t.Cleanup(server.Close)
	return server
}

// TestGeneration_SubscriberRemediationFallbackIsUnused proves the opener's default ban decides an
// unknown type, not a subscriber's lapiRemediationFallback: ignore.
func TestGeneration_SubscriberRemediationFallbackIsUnused(t *testing.T) {
	host := mustHost(t, throttleLiveLAPI(t).URL)
	generation := newGeneration(t, time.Second)

	subscriberCfg := lapiSubscriberConfig(host)
	subscriberCfg.LapiRemediationFallback = configuration.LapiRemediationFallbackIgnore
	owner := generationRoute("owner", "owner", lapiOwnerConfig(host, "shared"))
	subscriber := generationRoute("subscriber", "subscriber", subscriberCfg)
	if failed := generation.Apply([]traefikemulator.Route{owner, subscriber}); failed != nil {
		t.Fatal(failed)
	}
	if status := serveStatus(t, generation, "subscriber"); status != http.StatusForbidden {
		t.Fatalf("subscriber status %d, want %d (opener default ban decides throttle)", status, http.StatusForbidden)
	}
}

// TestGeneration_OpenerRemediationFallbackIgnorePasses proves the opener's ignore lets a
// throttle-only IP through on a subscriber that left the knob unset.
func TestGeneration_OpenerRemediationFallbackIgnorePasses(t *testing.T) {
	host := mustHost(t, throttleLiveLAPI(t).URL)
	generation := newGeneration(t, time.Second)

	ownerCfg := lapiOwnerConfig(host, "shared")
	ownerCfg.LapiRemediationFallback = configuration.LapiRemediationFallbackIgnore
	owner := generationRoute("owner", "owner", ownerCfg)
	subscriber := generationRoute("subscriber", "subscriber", lapiSubscriberConfig(host))
	if failed := generation.Apply([]traefikemulator.Route{owner, subscriber}); failed != nil {
		t.Fatal(failed)
	}
	if status := serveStatus(t, generation, "subscriber"); status != http.StatusOK {
		t.Fatalf("subscriber status %d, want %d (opener ignore skips throttle)", status, http.StatusOK)
	}
}

// TestGeneration_IgnoreFallbackKeepsLapiFailureAction proves an unreachable LAPI still follows
// bouncerLapiFailureAction (ban), whatever lapiRemediationFallback says.
func TestGeneration_IgnoreFallbackKeepsLapiFailureAction(t *testing.T) {
	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(failing.Close)
	host := mustHost(t, failing.URL)
	generation := newGeneration(t, time.Second)

	ownerCfg := lapiOwnerConfig(host, "shared")
	ownerCfg.LapiRemediationFallback = configuration.LapiRemediationFallbackIgnore
	ownerCfg.BouncerLapiFailureAction = configuration.FailureActionBan
	if failed := generation.Apply([]traefikemulator.Route{generationRoute("owner", "owner", ownerCfg)}); failed != nil {
		t.Fatal(failed)
	}
	if status := serveStatus(t, generation, "owner"); status != http.StatusForbidden {
		t.Fatalf("owner status %d, want %d (LAPI failure action ban)", status, http.StatusForbidden)
	}
}

package crowdsec_bouncer_traefik_plugin //nolint:revive,stylecheck

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/lapi"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/reclaim"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/traefikemulator"
)

func pluginConstructor(ctx context.Context, next http.Handler, config any, name string) (http.Handler, error) {
	cfg, ok := config.(*configuration.Config)
	if !ok {
		return nil, fmt.Errorf("config type %T", config)
	}
	return New(ctx, next, cfg, name)
}

func generationRoute(name, middlewareName string, cfg *configuration.Config) traefikemulator.Route {
	return traefikemulator.Route{
		Name:           name,
		MiddlewareName: middlewareName,
		Next:           testNextOK(),
		Config:         cfg,
	}
}

func lapiOwnerConfig(host, instanceName string) *configuration.Config {
	cfg := cfgLiveAt(host)
	cfg.CrowdsecLapiInstanceName = instanceName
	cfg.StreamStartupBlock = true
	return cfg
}

func lapiSubscriberConfig(host string) *configuration.Config {
	cfg := lapiOwnerConfig(host, "shared")
	cfg.CrowdsecLapiEnabled = false
	return cfg
}

func newGeneration(t *testing.T, grace time.Duration) *traefikemulator.Emulator {
	t.Helper()
	reclaim.ResetForTestWith(grace)
	t.Cleanup(func() { reclaim.ResetForTest() })
	generation := traefikemulator.New(pluginConstructor)
	t.Cleanup(func() { generation.Stop() })
	return generation
}

func serveStatus(t *testing.T, generation *traefikemulator.Emulator, routeName string) int {
	t.Helper()
	recorder := httptest.NewRecorder()
	if !generation.Serve(routeName, recorder, reqForIP("203.0.113.9")) {
		t.Fatalf("route %s is not in this generation", routeName)
	}
	return recorder.Code
}

func routeClient(t *testing.T, generation *traefikemulator.Emulator, routeName string) *lapi.Client {
	t.Helper()
	handler, ok := generation.Handler(routeName)
	if !ok {
		t.Fatalf("route %s missing", routeName)
	}
	return testRoute(t, handler).LapiClient()
}

func requireBound(t *testing.T, generation *traefikemulator.Emulator, routeName string, client *lapi.Client) {
	t.Helper()
	if serveStatus(t, generation, routeName) != http.StatusOK {
		t.Fatalf("%s must be bound", routeName)
	}
	if routeClient(t, generation, routeName) != client {
		t.Fatalf("%s is not bound to the generation client", routeName)
	}
}

func waitFor(t *testing.T, timeout time.Duration, ready func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if ready() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition was not met before the deadline")
}

func TestGeneration_SubscriberBeforeOwnerWithinGrace(t *testing.T) {
	var zero int64
	srv := liveLAPI(t, nil, &zero)
	t.Cleanup(func() { srv.Close() })
	host := mustHost(t, srv.URL)
	generation := newGeneration(t, time.Second)

	owner := generationRoute("owner", "owner", lapiOwnerConfig(host, "shared"))
	subscriber := generationRoute("subscriber", "subscriber", lapiSubscriberConfig(host))
	for range 2 {
		if failed := generation.Apply([]traefikemulator.Route{subscriber, owner}); failed != nil {
			t.Fatal(failed)
		}
	}
	requireBound(t, generation, "subscriber", routeClient(t, generation, "owner"))
}

func TestGeneration_OwnerBeforeSubscriberWithinGrace(t *testing.T) {
	var zero int64
	srv := liveLAPI(t, nil, &zero)
	t.Cleanup(func() { srv.Close() })
	host := mustHost(t, srv.URL)
	generation := newGeneration(t, time.Second)

	owner := generationRoute("owner", "owner", lapiOwnerConfig(host, "shared"))
	subscriber := generationRoute("subscriber", "subscriber", lapiSubscriberConfig(host))
	for range 2 {
		if failed := generation.Apply([]traefikemulator.Route{owner, subscriber}); failed != nil {
			t.Fatal(failed)
		}
	}
	requireBound(t, generation, "subscriber", routeClient(t, generation, "owner"))
}

func TestGeneration_ReloadAfterGraceBindsNewClient(t *testing.T) {
	grace := 200 * time.Millisecond
	var zero int64
	srv := liveLAPI(t, nil, &zero)
	t.Cleanup(func() { srv.Close() })
	host := mustHost(t, srv.URL)
	generation := newGeneration(t, grace)

	owner := generationRoute("owner", "owner", lapiOwnerConfig(host, "shared"))
	subscriber := generationRoute("subscriber", "subscriber", lapiSubscriberConfig(host))
	if failed := generation.Apply([]traefikemulator.Route{owner, subscriber}); failed != nil {
		t.Fatal(failed)
	}
	first := routeClient(t, generation, "subscriber")
	// Apply constructs inside the grace window. End the generation, let grace finish, then construct again.
	generation.Stop()
	waitFor(t, grace+time.Second, first.ClosedForTest)
	if failed := generation.Apply([]traefikemulator.Route{owner, subscriber}); failed != nil {
		t.Fatal(failed)
	}
	second := routeClient(t, generation, "subscriber")
	if second == nil || second == first {
		t.Fatal("reload after grace must bind a new client")
	}
	if serveStatus(t, generation, "subscriber") != http.StatusOK {
		t.Fatal("subscriber must be bound to the new client")
	}
}

func TestGeneration_OwnerRemovedSubscriberKeptUntilGrace(t *testing.T) {
	grace := 200 * time.Millisecond
	var zero int64
	srv := liveLAPI(t, nil, &zero)
	t.Cleanup(func() { srv.Close() })
	host := mustHost(t, srv.URL)
	generation := newGeneration(t, grace)

	owner := generationRoute("owner", "owner", lapiOwnerConfig(host, "shared"))
	subscriber := generationRoute("subscriber", "subscriber", lapiSubscriberConfig(host))
	if failed := generation.Apply([]traefikemulator.Route{owner, subscriber}); failed != nil {
		t.Fatal(failed)
	}
	client := routeClient(t, generation, "owner")
	if failed := generation.Apply([]traefikemulator.Route{subscriber}); failed != nil {
		t.Fatal(failed)
	}
	requireBound(t, generation, "subscriber", client)

	waitFor(t, grace+time.Second, func() bool {
		return client.ClosedForTest() && serveStatus(t, generation, "subscriber") == http.StatusServiceUnavailable
	})
}

func TestGeneration_SubscriberRemovedOwnerKept(t *testing.T) {
	var zero int64
	srv := liveLAPI(t, nil, &zero)
	t.Cleanup(func() { srv.Close() })
	host := mustHost(t, srv.URL)
	generation := newGeneration(t, time.Second)

	owner := generationRoute("owner", "owner", lapiOwnerConfig(host, "shared"))
	subscriber := generationRoute("subscriber", "subscriber", lapiSubscriberConfig(host))
	if failed := generation.Apply([]traefikemulator.Route{owner, subscriber}); failed != nil {
		t.Fatal(failed)
	}
	client := routeClient(t, generation, "owner")
	if failed := generation.Apply([]traefikemulator.Route{owner}); failed != nil {
		t.Fatal(failed)
	}
	if _, ok := generation.Handler("subscriber"); ok {
		t.Fatal("removed subscriber must be absent")
	}
	requireBound(t, generation, "owner", client)
}

func TestGeneration_SecondPublisherAbsent(t *testing.T) {
	var zero int64
	srv := liveLAPI(t, nil, &zero)
	t.Cleanup(func() { srv.Close() })
	host := mustHost(t, srv.URL)
	generation := newGeneration(t, time.Second)

	first := generationRoute("first", "owner-a", lapiOwnerConfig(host, "shared"))
	second := generationRoute("second", "owner-b", lapiOwnerConfig(host, "shared"))
	failed := generation.Apply([]traefikemulator.Route{first, second})
	if failed["second"] == nil || !strings.Contains(failed["second"].Error(), "held by") {
		t.Fatalf("second publisher error %v", failed["second"])
	}
	if _, ok := generation.Handler("second"); ok {
		t.Fatal("rejected publisher must be absent")
	}
	if serveStatus(t, generation, "first") != http.StatusOK {
		t.Fatal("first publisher must still serve")
	}
	if routeClient(t, generation, "first") == nil {
		t.Fatal("first publisher must still be the published client")
	}
}

func TestGeneration_OwnerLegDisabledUnbindsSubscriber(t *testing.T) {
	var zero int64
	srv := liveLAPI(t, nil, &zero)
	t.Cleanup(func() { srv.Close() })
	host := mustHost(t, srv.URL)
	generation := newGeneration(t, time.Second)

	ownerCfg := lapiOwnerConfig(host, "shared")
	owner := generationRoute("owner", "owner", ownerCfg)
	subscriber := generationRoute("subscriber", "subscriber", lapiSubscriberConfig(host))
	if failed := generation.Apply([]traefikemulator.Route{owner, subscriber}); failed != nil {
		t.Fatal(failed)
	}
	client := routeClient(t, generation, "owner")
	ownerCfg.CrowdsecLapiEnabled = false
	if failed := generation.Apply([]traefikemulator.Route{owner, subscriber}); failed != nil {
		t.Fatal(failed)
	}
	if serveStatus(t, generation, "subscriber") != http.StatusServiceUnavailable {
		t.Fatal("ClearPublisher must unbind the subscriber")
	}
	waitFor(t, time.Second, client.SleepingForTest)
	if client.ClosedForTest() {
		t.Fatal("disabling the leg must sleep the client, not close it")
	}
}

func TestGeneration_TwoHoldersThenOne(t *testing.T) {
	var zero int64
	srv := liveLAPI(t, nil, &zero)
	t.Cleanup(func() { srv.Close() })
	host := mustHost(t, srv.URL)
	generation := newGeneration(t, time.Second)

	left := generationRoute("left", "holder", lapiOwnerConfig(host, "holder"))
	right := generationRoute("right", "holder", lapiOwnerConfig(host, "holder"))
	if failed := generation.Apply([]traefikemulator.Route{left, right}); failed != nil {
		t.Fatal(failed)
	}
	client := routeClient(t, generation, "left")
	requireBound(t, generation, "right", client)
	if failed := generation.Apply([]traefikemulator.Route{left}); failed != nil {
		t.Fatal(failed)
	}
	if _, ok := generation.Handler("right"); ok {
		t.Fatal("dropped holder must be absent")
	}
	requireBound(t, generation, "left", client)
}

func TestGeneration_AppSecSubscriberBothOrders(t *testing.T) {
	appsecSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"action":"allow"}`))
	}))
	t.Cleanup(func() { appsecSrv.Close() })
	host := mustHost(t, appsecSrv.URL)
	generation := newGeneration(t, time.Second)

	owner := generationRoute("owner", "owner", appsecOwnerConfig(host))
	subscriber := generationRoute("subscriber", "subscriber", appsecSubscriberConfig())
	for _, routes := range [][]traefikemulator.Route{
		{owner, subscriber},
		{subscriber, owner},
	} {
		if failed := generation.Apply(routes); failed != nil {
			t.Fatal(failed)
		}
		if serveStatus(t, generation, "subscriber") != http.StatusOK {
			t.Fatal("AppSec subscriber must be bound")
		}
	}
}

func appsecOwnerConfig(host string) *configuration.Config {
	cfg := getTestConfig()
	cfg.Enabled = false
	cfg.CrowdsecLapiEnabled = false
	cfg.CrowdsecLapiKey = ""
	cfg.CrowdsecAppsecEnabled = true
	cfg.CrowdsecAppsecInstanceName = "shared"
	cfg.CrowdsecAppsecScheme = "http"
	cfg.CrowdsecAppsecHost = host
	cfg.CrowdsecAppsecPath = "/"
	cfg.CrowdsecAppsecKey = "test-key"
	cfg.CrowdsecAppsecTLSInsecureVerify = true
	cfg.CrowdsecAppsecBodyLimit = 10485760
	cfg.HTTPTimeoutSeconds = 2
	return cfg
}

func appsecSubscriberConfig() *configuration.Config {
	cfg := getTestConfig()
	cfg.Enabled = true
	cfg.CrowdsecLapiEnabled = false
	cfg.CrowdsecLapiKey = ""
	cfg.CrowdsecAppsecEnabled = false
	cfg.CrowdsecAppsecInstanceName = "shared"
	cfg.StreamStartupBlock = true
	return cfg
}

func mustHost(t *testing.T, rawURL string) string {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	return parsed.Host
}

package bouncer

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/lapi"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/modsecurity"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/reclaim"
)

// newTestConnectionSubscriber builds router traefikName through New, the way a Traefik reload builds it: a new
// Bouncer subscribed to LAPI and ModSec instance instanceName, logging to log, with no client yet.
func newTestConnectionSubscriber(t *testing.T, traefikName, instanceName string, log *slog.Logger) *Bouncer {
	t.Helper()
	cfg := configuration.New()
	cfg.BouncerEnabled = true
	cfg.LapiInstanceName = instanceName
	cfg.ModsecInstanceName = instanceName
	b, err := New(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), traefikName, cfg, Subscriptions{LAPI: true, ModSec: true}, log)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// newTestModSecClient is a ModSec client with its own incarnation, closed when the test ends.
func newTestModSecClient(t *testing.T) *modsecurity.Client {
	t.Helper()
	cfg := configuration.New()
	cfg.ModsecURL = "http://127.0.0.1:1"
	client, err := modsecurity.New(cfg, logger.New("ERROR", ""), "test", "modsec-owner", "modsec-owner")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	return client
}

// newTestLAPIClient is an in-memory LAPI client with its own incarnation.
func newTestLAPIClient() *lapi.Client {
	client, _ := lapi.NewTestClient(logger.New("ERROR", ""))
	return client
}

// assertConnectionLines checks that sink holds wantWarn connection-unavailable WARN lines and wantInfo
// connection-available INFO lines naming router traefikName, leg, and instance instanceName.
func assertConnectionLines(t *testing.T, sink *syncLogSink, step, traefikName, leg, instanceName string, wantWarn, wantInfo int) {
	t.Helper()
	logged := sink.String()
	attrs := []string{`"traefikName":"` + traefikName + `"`, `"leg":"` + leg + `"`, `"instanceName":"` + instanceName + `"`}
	if got := countLogLines(logged, append([]string{`"level":"WARN"`, `"msg":"` + msgConnectionUnavailable + `"`}, attrs...)...); got != wantWarn {
		t.Fatalf("%s: %s/%s/%s WARN %q lines=%d want %d: %s", step, traefikName, leg, instanceName, msgConnectionUnavailable, got, wantWarn, logged)
	}
	if got := countLogLines(logged, append([]string{`"level":"INFO"`, `"msg":"` + msgConnectionAvailable + `"`}, attrs...)...); got != wantInfo {
		t.Fatalf("%s: %s/%s/%s INFO %q lines=%d want %d: %s", step, traefikName, leg, instanceName, msgConnectionAvailable, got, wantInfo, logged)
	}
}

// TestConnection_unavailableLogsOnTransitions proves a LAPI subscriber logs one WARN when its connection is not
// published and one INFO when a client binds again, never per request, while every request still gets the LAPI
// failure action (ban by default). The empty first delivery is the Yaegi order: a router built before its owner,
// or one naming an instance no middleware shares, warns at once.
func TestConnection_unavailableLogsOnTransitions(t *testing.T) {
	ResetConnectionWarningsForTest()
	t.Cleanup(ResetConnectionWarningsForTest)
	log, sink := newTestLogSink(slog.LevelInfo)
	b := newTestConnectionSubscriber(t, "app-a", "shared", log)
	empty := reclaim.Published{Value: (*lapi.Client)(nil)}

	// No connection: one WARN however often the empty value is delivered or requests arrive; requests are banned.
	b.ReceiveLAPI(empty)
	b.ReceiveLAPI(empty)
	for range 3 {
		rw := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "198.51.100.30:1234"
		b.ServeHTTP(rw, req)
		if rw.Code != http.StatusForbidden {
			t.Fatalf("no connection: status %d, want the LAPI failure action's 403", rw.Code)
		}
	}
	assertConnectionLines(t, sink, "no connection", "app-a", "lapi", "shared", 1, 0)

	// The connection arrives: one INFO naming its incarnation; the same client again and a replace log nothing.
	first := newTestLAPIClient()
	b.ReceiveLAPI(reclaim.Published{Value: first})
	b.ReceiveLAPI(reclaim.Published{Value: first})
	b.ReceiveLAPI(reclaim.Published{Value: newTestLAPIClient()})
	assertConnectionLines(t, sink, "bound", "app-a", "lapi", "shared", 1, 1)
	if got := countLogLines(sink.String(), `"msg":"`+msgConnectionAvailable+`"`, `"incarnation":"`+first.Incarnation()+`"`); got != 1 {
		t.Fatalf("INFO %q with incarnation %s lines=%d want 1: %s", msgConnectionAvailable, first.Incarnation(), got, sink.String())
	}

	// The owner goes away and comes back: one more WARN and one more INFO.
	b.ReceiveLAPI(empty)
	b.ReceiveLAPI(reclaim.Published{Value: newTestLAPIClient()})
	assertConnectionLines(t, sink, "second outage", "app-a", "lapi", "shared", 2, 2)

	// The rate-limit lines are the rate-limit leg's alone.
	if got := countLogLines(sink.String(), `"msg":"`+msgRateLimitOwnerUnavailable+`"`); got != 0 {
		t.Fatalf("LAPI outage logged %d rate-limit owner lines, want 0: %s", got, sink.String())
	}
}

// TestConnection_warningIsPendingPerRouterNameAndLeg proves the WARN is pending per router name and leg, not per
// Bouncer: a rebuilt subscriber neither repeats the WARN nor misses the INFO, each leg answers only its own WARN,
// a router rebuilt without a leg drops that leg's pending WARN without a line, and one rebuilt on another
// instance name warns for that name.
func TestConnection_warningIsPendingPerRouterNameAndLeg(t *testing.T) {
	ResetConnectionWarningsForTest()
	t.Cleanup(ResetConnectionWarningsForTest)
	log, sink := newTestLogSink(slog.LevelInfo)
	emptyLAPI := reclaim.Published{Value: (*lapi.Client)(nil)}
	emptyModSec := reclaim.Published{Value: (*modsecurity.Client)(nil)}

	// A router built before its owners, or naming an instance no middleware shares: one WARN per leg.
	first := newTestConnectionSubscriber(t, "app-a", "shared", log)
	first.ReceiveLAPI(emptyLAPI)
	first.ReceiveModSec(emptyModSec)
	assertConnectionLines(t, sink, "built before the owners", "app-a", "lapi", "shared", 1, 0)
	assertConnectionLines(t, sink, "built before the owners", "app-a", "modsec", "shared", 1, 0)

	// A reload rebuilds app-a while both are still missing: the same outage, no second WARN.
	rebuilt := newTestConnectionSubscriber(t, "app-a", "shared", log)
	rebuilt.ReceiveLAPI(emptyLAPI)
	rebuilt.ReceiveModSec(emptyModSec)
	assertConnectionLines(t, sink, "rebuilt without the owners", "app-a", "lapi", "shared", 1, 0)
	assertConnectionLines(t, sink, "rebuilt without the owners", "app-a", "modsec", "shared", 1, 0)

	// Another router name keeps its own WARN.
	appB := newTestConnectionSubscriber(t, "app-b", "shared", log)
	appB.ReceiveLAPI(emptyLAPI)
	assertConnectionLines(t, sink, "app-b without the owner", "app-b", "lapi", "shared", 1, 0)

	// LAPI binds on the rebuilt app-a: one INFO for app-a/lapi only; the older instance binding later logs nothing.
	lapiClient := newTestLAPIClient()
	rebuilt.ReceiveLAPI(reclaim.Published{Value: lapiClient})
	first.ReceiveLAPI(reclaim.Published{Value: lapiClient})
	assertConnectionLines(t, sink, "lapi bound", "app-a", "lapi", "shared", 1, 1)
	assertConnectionLines(t, sink, "lapi bound", "app-a", "modsec", "shared", 1, 0)
	assertConnectionLines(t, sink, "lapi bound", "app-b", "lapi", "shared", 1, 0)

	// ModSec binds: its own INFO.
	rebuilt.ReceiveModSec(reclaim.Published{Value: newTestModSecClient(t)})
	assertConnectionLines(t, sink, "modsec bound", "app-a", "modsec", "shared", 1, 1)

	// app-b is rebuilt without LAPI: its pending WARN is dropped, so a later bind of app-b logs no INFO.
	if _, err := New(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), "app-b", configuration.New(), Subscriptions{}, log); err != nil {
		t.Fatal(err)
	}
	resubscribed := newTestConnectionSubscriber(t, "app-b", "shared", log)
	resubscribed.ReceiveLAPI(reclaim.Published{Value: newTestLAPIClient()})
	assertConnectionLines(t, sink, "dropped by an unsubscribed rebuild", "app-b", "lapi", "shared", 1, 0)

	// app-b is rebuilt on instance other, which nothing publishes: the WARN and its INFO name other.
	renamed := newTestConnectionSubscriber(t, "app-b", "other", log)
	renamed.ReceiveLAPI(emptyLAPI)
	assertConnectionLines(t, sink, "renamed to an unpublished instance", "app-b", "lapi", "other", 1, 0)
	renamed.ReceiveLAPI(reclaim.Published{Value: newTestLAPIClient()})
	assertConnectionLines(t, sink, "renamed instance bound", "app-b", "lapi", "other", 1, 1)
}

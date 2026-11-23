package lapi

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/admission"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionstore"
	logger "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
	"github.com/david-garcia-garcia/traefik-middleware-utilities/backendbackoff"
)

// testGateLAPI is a mock LAPI whose live answer the test switches between requests. It counts
// every request it receives.
type testGateLAPI struct {
	server   *httptest.Server
	hits     int64
	status   int64        // HTTP status of the next answers
	ipBody   atomic.Value // string body of an ip= query when status is 200
	scopeHit int64        // scope= queries received
	onIP     atomic.Value // func(): optional hook run while an ip= query is in flight
}

// newTestGateLAPI starts the mock with status 200 and a "null" body.
func newTestGateLAPI(t *testing.T) *testGateLAPI {
	t.Helper()
	mock := &testGateLAPI{status: http.StatusOK}
	mock.ipBody.Store("null")
	mock.server = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		atomic.AddInt64(&mock.hits, 1)
		isScope := req.URL.Query().Get("scope") != ""
		if isScope {
			atomic.AddInt64(&mock.scopeHit, 1)
		} else if hook, ok := mock.onIP.Load().(func()); ok {
			hook()
		}
		status := int(atomic.LoadInt64(&mock.status))
		if status != http.StatusOK {
			rw.WriteHeader(status)
			return
		}
		body := "null"
		if !isScope {
			body, _ = mock.ipBody.Load().(string)
		}
		if _, err := rw.Write([]byte(body)); err != nil {
			t.Errorf("mock LAPI write: %v", err)
		}
	}))
	t.Cleanup(mock.server.Close)
	return mock
}

// setStatus switches the status of the next answers.
func (m *testGateLAPI) setStatus(status int) {
	atomic.StoreInt64(&m.status, int64(status))
}

// hitCount is the number of requests the mock received.
func (m *testGateLAPI) hitCount() int64 {
	return atomic.LoadInt64(&m.hits)
}

// newTestGatedClient builds a Client through New in mode against mock, with a live gate period of periodSecs.
func newTestGatedClient(t *testing.T, mock *testGateLAPI, mode string, periodSecs int64, log *slog.Logger) *Client {
	t.Helper()
	serverURL, err := url.Parse(mock.server.URL)
	if err != nil {
		t.Fatal(err)
	}
	cfg := testLiveConfig(60)
	cfg.LapiMode = mode
	cfg.LapiHost = serverURL.Host
	cfg.LapiUnhealthyBackOffPeriodSecs = periodSecs
	store := decisionstore.NewMemory(logger.New("ERROR", ""))
	client, err := New(cfg, log, "test", store, "router", "bind")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	return client
}

// tripTestGate spends the gate budget with admission.TripFailures failing lookups (mock answers 503).
func tripTestGate(t *testing.T, client *Client, mock *testGateLAPI) {
	t.Helper()
	mock.setStatus(http.StatusServiceUnavailable)
	for i := range admission.TripFailures {
		if _, _, err := client.LiveLookup("192.0.2.1", nil, 60); err == nil || errors.Is(err, ErrGateSkip) {
			t.Fatalf("failing lookup %d: err=%v, want a real failure", i, err)
		}
	}
}

// TestNew_liveGatePerMode builds the gate only in live and none with a positive period, and Close closes it.
func TestNew_liveGatePerMode(t *testing.T) {
	mock := newTestGateLAPI(t)
	for _, mode := range []string{configuration.LiveMode, configuration.NoneMode} {
		client := newTestGatedClient(t, mock, mode, configuration.DefaultLapiUnhealthyBackOffPeriodSecs, logger.New("ERROR", ""))
		gate := client.GateForTest()
		if gate == nil {
			t.Fatalf("%s with the default period must build a gate", mode)
		}
		client.Close()
		if _, err := gate.Inner().Report(backendbackoff.Permit{}, true); err == nil {
			t.Fatalf("%s: Close must close the gate", mode)
		}
		if zero := newTestGatedClient(t, mock, mode, 0, logger.New("ERROR", "")); zero.GateForTest() != nil {
			t.Fatalf("%s with period 0 must not build a gate", mode)
		}
	}
	stream := newTestGatedClient(t, mock, configuration.StreamMode, 10, logger.New("ERROR", ""))
	if stream.GateForTest() != nil {
		t.Fatal("stream must not build a gate")
	}
	alone := testLiveConfig(60)
	alone.LapiMode = configuration.AloneMode
	alone.LapiUnhealthyBackOffPeriodSecs = 10
	if gate, err := newLiveGate(alone, logger.New("ERROR", "")); err != nil || gate != nil {
		t.Fatalf("alone gate=%v err=%v, want none", gate, err)
	}
}

// TestLiveLookup_gateTripsAndSkips proves 5 failing live GETs trip the gate and the next lookup
// sends nothing, returns ErrGateSkip with a non-active kind, and caches nothing.
func TestLiveLookup_gateTripsAndSkips(t *testing.T) {
	for _, mode := range []string{configuration.LiveMode, configuration.NoneMode} {
		t.Run(mode, func(t *testing.T) {
			mock := newTestGateLAPI(t)
			client := newTestGatedClient(t, mock, mode, 10, logger.New("ERROR", ""))
			tripTestGate(t, client, mock)
			if got := mock.hitCount(); got != admission.TripFailures {
				t.Fatalf("hits=%d want %d", got, admission.TripFailures)
			}
			kind, _, err := client.LiveLookup("192.0.2.1", map[string]string{"username": "alice"}, 60)
			if !errors.Is(err, ErrGateSkip) {
				t.Fatalf("err=%v want ErrGateSkip", err)
			}
			if decisionscope.IsActiveRemediation(kind) {
				t.Fatalf("skip kind=%q must not be active", kind)
			}
			if got := mock.hitCount(); got != admission.TripFailures {
				t.Fatalf("skipped lookup sent a GET (IP or header scope): hits=%d", got)
			}
			if cached, _, _, _ := client.LookupRemediation("192.0.2.1", net.ParseIP("192.0.2.1"), nil); cached != "" {
				t.Fatalf("skip cached %q for the client address", cached)
			}
		})
	}
}

// TestLiveLookup_statusClassification pins which live answers spend the gate budget: 429 trips,
// 401 and a 200 with bad JSON never do.
func TestLiveLookup_statusClassification(t *testing.T) {
	t.Run("429 trips", func(t *testing.T) {
		mock := newTestGateLAPI(t)
		client := newTestGatedClient(t, mock, configuration.LiveMode, 10, logger.New("ERROR", ""))
		mock.setStatus(http.StatusTooManyRequests)
		for range admission.TripFailures {
			_, _, _ = client.LiveLookup("192.0.2.1", nil, 60)
		}
		if _, _, err := client.LiveLookup("192.0.2.1", nil, 60); !errors.Is(err, ErrGateSkip) {
			t.Fatalf("err=%v want ErrGateSkip after 5 x 429", err)
		}
	})
	t.Run("401 never trips", func(t *testing.T) {
		mock := newTestGateLAPI(t)
		client := newTestGatedClient(t, mock, configuration.LiveMode, 10, logger.New("ERROR", ""))
		mock.setStatus(http.StatusUnauthorized)
		for i := range 4 * admission.TripFailures {
			kind, _, err := client.LiveLookup("192.0.2.1", nil, 60)
			if err == nil || errors.Is(err, ErrGateSkip) || decisionscope.IsActiveRemediation(kind) {
				t.Fatalf("lookup %d: kind=%q err=%v, want a failure that is not a skip", i, kind, err)
			}
		}
		if got := mock.hitCount(); got != 4*admission.TripFailures {
			t.Fatalf("hits=%d want every 401 lookup to reach LAPI", got)
		}
	})
	t.Run("bad JSON is a success for the gate", func(t *testing.T) {
		mock := newTestGateLAPI(t)
		client := newTestGatedClient(t, mock, configuration.LiveMode, 10, logger.New("ERROR", ""))
		mock.ipBody.Store("not json")
		for i := range 4 * admission.TripFailures {
			if _, _, err := client.LiveLookup("192.0.2.1", nil, 60); err == nil || errors.Is(err, ErrGateSkip) {
				t.Fatalf("lookup %d: err=%v, want a parse failure that is not a skip", i, err)
			}
		}
	})
}

// TestLiveLookup_skippedScopeAfterAnsweredIP trips the gate while the client-address GET is in flight,
// so the header-scope GET of the same lookup is denied.
func TestLiveLookup_skippedScopeAfterAnsweredIP(t *testing.T) {
	scopes := map[string]string{"username": "alice"}
	t.Run("clean IP and skipped scope is a skip and caches nothing", func(t *testing.T) {
		mock := newTestGateLAPI(t)
		client := newTestGatedClient(t, mock, configuration.LiveMode, 10, logger.New("ERROR", ""))
		mock.onIP.Store(func() { tripTestGateDirectly(client) })
		kind, _, err := client.LiveLookup("192.0.2.1", scopes, 60)
		if !errors.Is(err, ErrGateSkip) || decisionscope.IsActiveRemediation(kind) {
			t.Fatalf("kind=%q err=%v want a non-active ErrGateSkip", kind, err)
		}
		if got := atomic.LoadInt64(&mock.scopeHit); got != 0 {
			t.Fatalf("scope GETs=%d want 0", got)
		}
		if cached, _, _, _ := client.LookupRemediation("192.0.2.1", net.ParseIP("192.0.2.1"), nil); cached != "" {
			t.Fatalf("a skipped scope must block the clean IP memo, cached %q", cached)
		}
	})
	t.Run("IP ban outranks a skipped scope", func(t *testing.T) {
		mock := newTestGateLAPI(t)
		client := newTestGatedClient(t, mock, configuration.LiveMode, 10, logger.New("ERROR", ""))
		mock.ipBody.Store(testLiveBanBody("Ip", "192.0.2.1"))
		mock.onIP.Store(func() { tripTestGateDirectly(client) })
		kind, _, _ := client.LiveLookup("192.0.2.1", scopes, 60)
		if kind != decisionscope.BannedValue {
			t.Fatalf("kind=%q want the IP ban", kind)
		}
	})
}

// tripTestGateDirectly spends the budget of client's gate without LAPI, for a test that needs the
// gate to trip between two GETs of one lookup.
func tripTestGateDirectly(client *Client) {
	for range admission.TripFailures {
		ticket, err := client.gate.Admit(context.Background())
		if err != nil || !ticket.Admitted {
			return
		}
		client.gate.Record(ticket, false)
	}
}

// TestLiveLookup_probeRecoversAndLogsOnce trips the gate, skips twice, then lets a probe through
// after the cooldown: one started line, one ended line, and the next lookup uses LAPI again.
func TestLiveLookup_probeRecoversAndLogsOnce(t *testing.T) {
	mock := newTestGateLAPI(t)
	log, sink := newTestLogSink(slog.LevelInfo)
	client := newTestGatedClient(t, mock, configuration.LiveMode, 10, log)
	now := time.Now()
	client.GateForTest().Inner().SetNowForTest(func() time.Time { return now })

	tripTestGate(t, client, mock)
	for range 2 {
		if _, _, err := client.LiveLookup("192.0.2.1", nil, 0); !errors.Is(err, ErrGateSkip) {
			t.Fatalf("err=%v want ErrGateSkip", err)
		}
	}
	mock.setStatus(http.StatusOK)
	now = now.Add(11 * time.Second)
	if kind, _, err := client.LiveLookup("192.0.2.1", nil, 0); err != nil || kind != decisionscope.NoBannedValue {
		t.Fatalf("probe kind=%q err=%v want a clean answer", kind, err)
	}
	if _, _, err := client.LiveLookup("192.0.2.2", nil, 0); err != nil {
		t.Fatalf("after recovery err=%v", err)
	}
	if got := mock.hitCount(); got != admission.TripFailures+2 {
		t.Fatalf("hits=%d want %d", got, admission.TripFailures+2)
	}
	client.Close()
	logged := sink.String()
	if got := strings.Count(logged, MsgBackoffStarted); got != 1 {
		t.Fatalf("%q logged %d times, want 1:\n%s", MsgBackoffStarted, got, logged)
	}
	if got := strings.Count(logged, MsgBackoffEnded); got != 1 {
		t.Fatalf("%q logged %d times, want 1:\n%s", MsgBackoffEnded, got, logged)
	}
	if strings.Contains(logged, "handleNoStreamCache:scopeQuery") {
		t.Fatalf("a skip must not log a scope WARN:\n%s", logged)
	}
}

// TestLiveLookup_zeroPeriodAlwaysQueries keeps 0 as the switch that turns the gate off.
func TestLiveLookup_zeroPeriodAlwaysQueries(t *testing.T) {
	mock := newTestGateLAPI(t)
	client := newTestGatedClient(t, mock, configuration.LiveMode, 0, logger.New("ERROR", ""))
	mock.setStatus(http.StatusServiceUnavailable)
	for i := range 4 * admission.TripFailures {
		if _, _, err := client.LiveLookup("192.0.2.1", nil, 60); err == nil || errors.Is(err, ErrGateSkip) {
			t.Fatalf("lookup %d: err=%v, want a real failure", i, err)
		}
	}
	if got := mock.hitCount(); got != 4*admission.TripFailures {
		t.Fatalf("hits=%d want every lookup to reach LAPI", got)
	}
}

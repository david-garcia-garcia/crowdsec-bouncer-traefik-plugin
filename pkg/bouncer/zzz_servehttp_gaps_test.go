package bouncer

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
	logger "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

func TestServeHTTP_DisabledSkipsBan(t *testing.T) {
	b, _, passed := testForcedDecisionBouncer(t, nil, nil, nil, true)
	b.enabled = false
	rw := httptest.NewRecorder()
	b.ServeHTTP(rw, testForcedDecisionRequest(""))
	if !*passed {
		t.Fatal("disabled bouncer must call next")
	}
	if rw.Code != http.StatusOK {
		t.Fatalf("disabled status = %d, want 200", rw.Code)
	}
}

func TestServeHTTP_StartupBlockMissingLAPI(t *testing.T) {
	b, _, passed := testForcedDecisionBouncer(t, nil, nil, nil, false)
	bindTestLAPI(b, nil)
	b.subscribeLAPI = true
	b.startupBlock = true
	b.lapiInstanceName = "shared"
	rw := httptest.NewRecorder()
	b.ServeHTTP(rw, testForcedDecisionRequest(""))
	if *passed {
		t.Fatal("startup block must not call next")
	}
	if rw.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing LAPI status = %d, want 503", rw.Code)
	}
}

func TestServeHTTP_StartupBlockMissingAppSec(t *testing.T) {
	b, _, passed := testForcedDecisionBouncer(t, nil, nil, nil, false)
	b.subscribeAppSec = true
	b.startupBlock = true
	b.appsecInstanceName = "shared"
	rw := httptest.NewRecorder()
	b.ServeHTTP(rw, testForcedDecisionRequest(""))
	if *passed {
		t.Fatal("startup block must not call next")
	}
	if rw.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing AppSec status = %d, want 503", rw.Code)
	}
}

func TestServeHTTP_UnboundLAPIUsesFailureAction(t *testing.T) {
	t.Run("ban", func(t *testing.T) {
		b, _, passed := testForcedDecisionBouncer(t, nil, nil, nil, false)
		bindTestLAPI(b, nil)
		b.subscribeLAPI = true
		b.lapiFailureAction = configuration.FailureActionBan
		rw := httptest.NewRecorder()
		b.ServeHTTP(rw, testForcedDecisionRequest(""))
		if *passed || rw.Code != http.StatusForbidden {
			t.Fatalf("unbound LAPI ban passed=%v status=%d", *passed, rw.Code)
		}
	})
	t.Run("passthrough", func(t *testing.T) {
		b, _, passed := testForcedDecisionBouncer(t, nil, nil, nil, false)
		bindTestLAPI(b, nil)
		b.subscribeLAPI = true
		b.lapiFailureAction = configuration.FailureActionPassthrough
		rw := httptest.NewRecorder()
		b.ServeHTTP(rw, testForcedDecisionRequest(""))
		if !*passed || rw.Code != http.StatusOK {
			t.Fatalf("unbound LAPI passthrough passed=%v status=%d", *passed, rw.Code)
		}
	})
}

func TestServeHTTP_StreamUnhealthyUsesFailureAction(t *testing.T) {
	t.Run("ban", func(t *testing.T) {
		b, client, passed := testForcedDecisionBouncer(t, nil, nil, nil, false)
		client.SetStreamHealthyForTest(false)
		b.lapiFailureAction = configuration.FailureActionBan
		rw := httptest.NewRecorder()
		b.ServeHTTP(rw, testForcedDecisionRequest(""))
		if *passed || rw.Code != http.StatusForbidden {
			t.Fatalf("unhealthy stream ban passed=%v status=%d", *passed, rw.Code)
		}
	})
	t.Run("passthrough", func(t *testing.T) {
		b, client, passed := testForcedDecisionBouncer(t, nil, nil, nil, false)
		client.SetStreamHealthyForTest(false)
		b.lapiFailureAction = configuration.FailureActionPassthrough
		rw := httptest.NewRecorder()
		b.ServeHTTP(rw, testForcedDecisionRequest(""))
		if !*passed || rw.Code != http.StatusOK {
			t.Fatalf("unhealthy stream passthrough passed=%v status=%d", *passed, rw.Code)
		}
	})
}

func TestServeHTTP_BadRemoteAddrBans(t *testing.T) {
	b, _, passed := testForcedDecisionBouncer(t, nil, nil, nil, false)
	req := testForcedDecisionRequest("")
	req.RemoteAddr = "not-a-socket"
	rw := httptest.NewRecorder()
	b.ServeHTTP(rw, req)
	if *passed || rw.Code != http.StatusForbidden {
		t.Fatalf("bad RemoteAddr passed=%v status=%d body=%q", *passed, rw.Code, rw.Body.String())
	}
	if !strings.Contains(rw.Body.String(), "banned") {
		t.Fatalf("body = %q, want ban template", rw.Body.String())
	}
}

func TestServeHTTP_UnparseableClientIPBans(t *testing.T) {
	b, _, passed := testForcedDecisionBouncer(t, nil, nil, nil, false)
	req := testForcedDecisionRequest("")
	req.Header.Set("X-Forwarded-For", "not-an-ip")
	rw := httptest.NewRecorder()
	b.ServeHTTP(rw, req)
	if *passed || rw.Code != http.StatusForbidden {
		t.Fatalf("unparseable client passed=%v status=%d", *passed, rw.Code)
	}
}

func TestReceiveLAPI_WarnsWhenHeaderScopeIsNotPolled(t *testing.T) {
	log, sink := newTestLogSink(slog.LevelWarn)
	b, _, _ := testForcedDecisionBouncer(t, log, nil, nil, false)
	b.decisionScopeHeaders = map[string]string{decisionscope.ScopeCountry: "CF-IPCountry"}
	b.receiveLAPI()
	b.receiveLAPI()
	logged := sink.String()
	if strings.Count(logged, "crowdsec bouncer stream scopes missing") != 1 {
		t.Fatalf("want one missing-scope WARN, got %s", logged)
	}
	if !strings.Contains(logged, "Country") {
		t.Fatalf("WARN must name Country, got %s", logged)
	}
}

func TestReceiveLAPI_QuietWhenNoHeaderScopes(t *testing.T) {
	log, sink := newTestLogSink(slog.LevelWarn)
	b, _, _ := testForcedDecisionBouncer(t, log, nil, nil, false)
	b.receiveLAPI()
	if strings.Contains(sink.String(), "stream scopes missing") {
		t.Fatalf("no header scopes must not warn, got %s", sink.String())
	}
}

func TestHandleNextServeHTTP_UnpublishedAppSecUsesFailureAction(t *testing.T) {
	newBouncer := func(action string) (*Bouncer, *bool) {
		passed := false
		b := &Bouncer{
			subscribeAppSec:       true,
			appsecFailureAction:   action,
			remediationStatusCode: http.StatusForbidden,
			log:                   logger.New("ERROR", ""),
			next: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				passed = true
			}),
		}
		return b, &passed
	}
	req := testClientRequest(httptest.NewRequest(http.MethodGet, "http://example.com/protected", nil), "192.0.2.10")

	t.Run("passthrough", func(t *testing.T) {
		b, passed := newBouncer(configuration.FailureActionPassthrough)
		b.handleNextServeHTTP(httptest.NewRecorder(), req)
		if !*passed {
			t.Fatal("unpublished AppSec passthrough must call next")
		}
	})
	t.Run("ban", func(t *testing.T) {
		b, passed := newBouncer(configuration.FailureActionBan)
		rw := httptest.NewRecorder()
		b.handleNextServeHTTP(rw, req)
		if *passed || rw.Code != http.StatusForbidden {
			t.Fatalf("unpublished AppSec ban passed=%v status=%d", *passed, rw.Code)
		}
	})
	t.Run("captcha", func(t *testing.T) {
		b, passed := newBouncer(configuration.FailureActionCaptcha)
		rw := httptest.NewRecorder()
		b.handleNextServeHTTP(rw, req)
		if *passed || rw.Code != http.StatusForbidden {
			t.Fatalf("unpublished AppSec captcha passed=%v status=%d", *passed, rw.Code)
		}
	})
}

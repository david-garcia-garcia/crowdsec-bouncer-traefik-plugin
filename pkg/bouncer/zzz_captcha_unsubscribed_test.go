package bouncer

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
)

func TestHandleRemediationServeHTTP_unsubscribedCaptchaWarnsThenBans(t *testing.T) {
	log, sink := newTestLogSink(slog.LevelWarn)
	b, originCalled := testCaptchaRoutingBouncer(t, nil)
	b.log = log
	req := httptest.NewRequest(http.MethodGet, "http://example.com/protected", nil)
	for range 2 {
		rw := httptest.NewRecorder()
		b.handleRemediationServeHTTP(rw, testClientRequest(req, testCaptchaRemoteIP), decisionscope.CaptchaValue, "cscli")
		if *originCalled {
			t.Fatal("unsubscribed captcha must not reach origin")
		}
		if rw.Code != http.StatusForbidden {
			t.Fatalf("unsubscribed captcha want 403, got %d", rw.Code)
		}
	}
	logged := sink.String()
	if strings.Count(logged, msgCaptchaUnsubscribed) != 2 {
		t.Fatalf("want WARN twice, got %s", logged)
	}
	if !strings.Contains(logged, `"leg":"captcha"`) {
		t.Fatalf("want leg=captcha, got %s", logged)
	}
	if !strings.Contains(logged, `"instanceName":""`) {
		t.Fatalf("want empty instanceName, got %s", logged)
	}
	if strings.Contains(logged, `"ip"`) {
		t.Fatalf("WARN must not emit ip, got %s", logged)
	}
}

func TestServeHTTP_forcedDecisionCaptchaUnsubscribedWarnsThenBans(t *testing.T) {
	log, sink := newTestLogSink(slog.LevelWarn)
	b, _, passed := testForcedDecisionBouncer(t, log, nil, nil, false)
	bindTestCaptcha(b, nil)
	rw := httptest.NewRecorder()
	b.ServeHTTP(rw, testForcedDecisionRequest("c"))
	if *passed {
		t.Fatal("unsubscribed forced captcha must not reach origin")
	}
	if rw.Code != http.StatusForbidden || !strings.Contains(rw.Body.String(), "banned") {
		t.Fatalf("status=%d body=%q", rw.Code, rw.Body.String())
	}
	logged := sink.String()
	if !strings.Contains(logged, msgCaptchaUnsubscribed) {
		t.Fatalf("want WARN %s, got %s", msgCaptchaUnsubscribed, logged)
	}
	if !strings.Contains(logged, `"leg":"captcha"`) {
		t.Fatalf("want leg=captcha, got %s", logged)
	}
	if strings.Contains(logged, `"ip"`) {
		t.Fatalf("WARN must not emit ip, got %s", logged)
	}
}

func TestHandleRemediationServeHTTP_subscribedUnpublishedDoesNotWarnUnsubscribed(t *testing.T) {
	log, sink := newTestLogSink(slog.LevelWarn)
	b, originCalled := testCaptchaRoutingBouncer(t, nil)
	b.log = log
	b.subscribeCaptcha = true
	req := httptest.NewRequest(http.MethodGet, "http://example.com/protected", nil)
	rw := httptest.NewRecorder()
	b.handleRemediationServeHTTP(rw, testClientRequest(req, testCaptchaRemoteIP), decisionscope.CaptchaValue, "cscli")
	if *originCalled {
		t.Fatal("subscribed unpublished captcha must not reach origin")
	}
	if rw.Code != http.StatusForbidden {
		t.Fatalf("subscribed unpublished captcha want 403, got %d", rw.Code)
	}
	if strings.Contains(sink.String(), msgCaptchaUnsubscribed) {
		t.Fatalf("subscribed unpublished must not emit %s, got %s", msgCaptchaUnsubscribed, sink.String())
	}
}

func TestServeHTTP_subscribedUnpublishedStartupBlockDoesNotWarnUnsubscribed(t *testing.T) {
	log, sink := newTestLogSink(slog.LevelWarn)
	b, originCalled := testCaptchaRoutingBouncer(t, nil)
	b.log = log
	b.enabled = true
	b.subscribeCaptcha = true
	b.startupBlock = true
	b.captchaInstanceName = "shared"
	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://example.com/protected", nil)
	req.RemoteAddr = "127.0.0.1:1"
	b.ServeHTTP(rw, req)
	if *originCalled {
		t.Fatal("startup-block captcha must not reach origin")
	}
	if rw.Code != http.StatusServiceUnavailable {
		t.Fatalf("subscribed unpublished startup block want 503, got %d", rw.Code)
	}
	logged := sink.String()
	if !strings.Contains(logged, msgBackendMissing) {
		t.Fatalf("want WARN %s, got %s", msgBackendMissing, logged)
	}
	if strings.Contains(logged, msgCaptchaUnsubscribed) {
		t.Fatalf("startup-block must not emit %s, got %s", msgCaptchaUnsubscribed, logged)
	}
}

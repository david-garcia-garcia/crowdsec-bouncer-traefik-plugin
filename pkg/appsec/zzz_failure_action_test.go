package appsec

import (
	"bytes"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

// failReadCloser is an AppSec response body that always fails on Read.
type failReadCloser struct{}

func (failReadCloser) Read([]byte) (int, error) { return 0, errors.New("boom") } // Read always fails.

func (failReadCloser) Close() error { return nil } // Close succeeds so drain can finish.

// failBodyRoundTripper returns a 200 whose body cannot be read.
type failBodyRoundTripper struct{}

// RoundTrip returns a live 200 with a body that fails to read.
func (failBodyRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       failReadCloser{},
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

// Test_appsecQuery_failureActionOnServerError proves HTTP 500/502/503/504 honor failure actions.
func Test_appsecQuery_failureActionOnServerError(t *testing.T) {
	for _, status := range []int{http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			appsecServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
				rw.WriteHeader(status)
			}))
			defer appsecServer.Close()
			appsecURL, _ := url.Parse(appsecServer.URL)
			client := newQueryClient(appsecURL, appsecServer.Client())
			req := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)

			decision, err := client.Query(withTestAddress(req), Policy{FailureAction: configuration.FailureActionBan})
			if err == nil {
				t.Fatalf("ban on %d expected an error", status)
			}
			if decision != nil {
				t.Fatalf("ban on %d returned decision %#v", status, decision)
			}

			decision, err = client.Query(withTestAddress(req), Policy{FailureAction: configuration.FailureActionPassthrough})
			if err != nil {
				t.Fatalf("passthrough on %d: %v", status, err)
			}
			if decision == nil || decision.Action != ActionAllow {
				t.Fatalf("passthrough on %d want allow, got %#v", status, decision)
			}

			_, err = client.Query(withTestAddress(req), Policy{FailureAction: configuration.FailureActionCaptcha})
			if !errors.Is(err, ErrFailureCaptcha) {
				t.Fatalf("captcha on %d want ErrFailureCaptcha, got %v", status, err)
			}
		})
	}
}

// Test_appsecQuery_failureActionOnUnauthorized proves HTTP 401 and other unexpected
// statuses honor failure actions. Dest still returns appsecQuery statusCode:401 on passthrough.
func Test_appsecQuery_failureActionOnUnauthorized(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusTeapot} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			appsecServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
				rw.WriteHeader(status)
			}))
			defer appsecServer.Close()
			appsecURL, _ := url.Parse(appsecServer.URL)
			client := newQueryClient(appsecURL, appsecServer.Client())
			req := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)

			decision, err := client.Query(withTestAddress(req), Policy{FailureAction: configuration.FailureActionBan})
			if err == nil {
				t.Fatalf("ban on %d expected an error", status)
			}
			want := "statusCode:" + strconv.Itoa(status)
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("ban on %d error %q want %s", status, err, want)
			}
			if decision != nil {
				t.Fatalf("ban on %d returned decision %#v", status, decision)
			}

			decision, err = client.Query(withTestAddress(req), Policy{FailureAction: configuration.FailureActionPassthrough})
			if err != nil {
				t.Fatalf("passthrough on %d: %v", status, err)
			}
			if decision == nil || decision.Action != ActionAllow {
				t.Fatalf("passthrough on %d want allow, got %#v", status, decision)
			}

			_, err = client.Query(withTestAddress(req), Policy{FailureAction: configuration.FailureActionCaptcha})
			if !errors.Is(err, ErrFailureCaptcha) {
				t.Fatalf("captcha on %d want ErrFailureCaptcha, got %v", status, err)
			}
		})
	}
}

func Test_appsecQuery_failureActionOnUnreachable(t *testing.T) {
	appsecServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
	}))
	appsecURL, _ := url.Parse(appsecServer.URL)
	client := newQueryClient(appsecURL, appsecServer.Client())
	appsecServer.Close()
	req := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)

	_, err := client.Query(withTestAddress(req), Policy{FailureAction: configuration.FailureActionBan})
	if err == nil {
		t.Fatal("ban on unreachable expected an error")
	}

	decision, err := client.Query(withTestAddress(req), Policy{FailureAction: configuration.FailureActionPassthrough})
	if err != nil {
		t.Fatalf("passthrough on unreachable: %v", err)
	}
	if decision == nil || decision.Action != ActionAllow {
		t.Fatalf("passthrough on unreachable want allow, got %#v", decision)
	}
}

// Test_appsecQuery_failureActionOnResponseBodyReadError proves a body io error uses FailureAction.
func Test_appsecQuery_failureActionOnResponseBodyReadError(t *testing.T) {
	client := NewTestClient(&url.URL{Scheme: "http", Host: "appsec.example"}, &http.Client{Transport: failBodyRoundTripper{}}, logger.New("INFO", ""))
	req := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)

	decision, err := client.Query(withTestAddress(req), Policy{FailureAction: configuration.FailureActionBan})
	if err == nil {
		t.Fatal("ban on response-body read error expected an error")
	}
	if !strings.Contains(err.Error(), "appsecQuery:readBody") {
		t.Fatalf("ban error %q want appsecQuery:readBody", err)
	}
	if decision != nil {
		t.Fatalf("ban on response-body read error returned decision %#v", decision)
	}

	decision, err = client.Query(withTestAddress(req), Policy{FailureAction: configuration.FailureActionPassthrough})
	if err != nil {
		t.Fatalf("passthrough on response-body read error: %v", err)
	}
	if decision == nil || decision.Action != ActionAllow {
		t.Fatalf("passthrough on response-body read error want allow, got %#v", decision)
	}

	_, err = client.Query(withTestAddress(req), Policy{FailureAction: configuration.FailureActionCaptcha})
	if !errors.Is(err, ErrFailureCaptcha) {
		t.Fatalf("captcha on response-body read error want ErrFailureCaptcha, got %v", err)
	}
}

// Test_appsecQuery_unparseable200Allows proves a 200 with a body that is not JSON is still allow.
func Test_appsecQuery_unparseable200Allows(t *testing.T) {
	appsecServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
		_, _ = rw.Write([]byte("not-json"))
	}))
	defer appsecServer.Close()
	appsecURL, _ := url.Parse(appsecServer.URL)
	decision, err := newQueryClient(appsecURL, appsecServer.Client()).Query(buildTestRequest(), Policy{FailureAction: configuration.FailureActionBan})
	if err != nil {
		t.Fatalf("unparseable 200: %v", err)
	}
	if decision == nil || decision.Action != ActionAllow {
		t.Fatalf("unparseable 200 want allow, got %#v", decision)
	}
}

// Test_appsecQuery_unparseable403Bans proves a 403 with a body that is not JSON bans and ignores FailureAction.
func Test_appsecQuery_unparseable403Bans(t *testing.T) {
	appsecServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusForbidden)
		_, _ = rw.Write([]byte("not-json"))
	}))
	defer appsecServer.Close()
	appsecURL, _ := url.Parse(appsecServer.URL)
	decision, err := newQueryClient(appsecURL, appsecServer.Client()).Query(buildTestRequest(), Policy{FailureAction: configuration.FailureActionPassthrough})
	if err == nil {
		t.Fatal("unparseable 403 with passthrough expected an error")
	}
	if decision != nil {
		t.Fatalf("unparseable 403 returned decision %#v", decision)
	}
}

// Test_appsecQuery_unexpectedStatusIgnoresBody proves a non-protocol status uses FailureAction even with a ban envelope.
func Test_appsecQuery_unexpectedStatusIgnoresBody(t *testing.T) {
	appsecServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusUnauthorized)
		_, _ = rw.Write([]byte(`{"action":"ban"}`))
	}))
	defer appsecServer.Close()
	appsecURL, _ := url.Parse(appsecServer.URL)
	decision, err := newQueryClient(appsecURL, appsecServer.Client()).Query(buildTestRequest(), Policy{FailureAction: configuration.FailureActionPassthrough})
	if err != nil {
		t.Fatalf("passthrough on 401 with ban JSON: %v", err)
	}
	if decision == nil || decision.Action != ActionAllow {
		t.Fatalf("passthrough on 401 want allow, got %#v", decision)
	}
}

// Test_appsecQuery_unexpectedStatusWarnsOnce proves the WARN is debounced on the message text.
func Test_appsecQuery_unexpectedStatusWarnsOnce(t *testing.T) {
	logger.ResetDebounceForTest()
	var statusCode int
	appsecServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(statusCode)
	}))
	defer appsecServer.Close()
	appsecURL, _ := url.Parse(appsecServer.URL)
	var sink bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&sink, &slog.HandlerOptions{Level: slog.LevelWarn}))
	client := NewTestClient(appsecURL, appsecServer.Client(), log)
	req := buildTestRequest()

	statusCode = http.StatusUnauthorized
	for range 2 {
		_, err := client.Query(req, Policy{FailureAction: configuration.FailureActionPassthrough})
		if err != nil {
			t.Fatalf("passthrough on 401: %v", err)
		}
	}
	if got := strings.Count(sink.String(), msgUnauthenticated); got != 1 {
		t.Fatalf("401 WARN count %d, log %s", got, sink.String())
	}
	if strings.Contains(sink.String(), msgUnexpectedListenerStatus) {
		t.Fatalf("401 logged the unexpected-status WARN: %s", sink.String())
	}

	statusCode = http.StatusBadGateway
	_, err := client.Query(req, Policy{FailureAction: configuration.FailureActionBan})
	if err == nil || !strings.Contains(err.Error(), "statusCode:502") {
		t.Fatalf("ban on 502: %v", err)
	}
	if got := strings.Count(sink.String(), msgUnexpectedListenerStatus); got != 1 {
		t.Fatalf("502 WARN count %d, log %s", got, sink.String())
	}
	if !strings.Contains(sink.String(), `"statusCode":502`) {
		t.Fatalf("502 WARN missing statusCode: %s", sink.String())
	}
	if strings.Contains(sink.String(), "appsecQuery:unreachable") {
		t.Fatalf("502 logged unreachable: %s", sink.String())
	}

	statusCode = http.StatusInternalServerError
	_, err = client.Query(req, Policy{FailureAction: configuration.FailureActionPassthrough})
	if err != nil {
		t.Fatalf("passthrough on 500: %v", err)
	}
	if got := strings.Count(sink.String(), msgUnexpectedListenerStatus); got != 1 {
		t.Fatalf("500 must not warn, count %d, log %s", got, sink.String())
	}
}

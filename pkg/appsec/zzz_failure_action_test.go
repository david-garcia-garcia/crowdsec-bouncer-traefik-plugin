package appsec

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	logger "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
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

func Test_appsecQuery_failureActionOn500(t *testing.T) {
	appsecServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusInternalServerError)
	}))
	defer appsecServer.Close()
	appsecURL, _ := url.Parse(appsecServer.URL)
	client := newQueryClient(appsecURL, appsecServer.Client())
	req := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)

	decision, err := client.Query("1.2.3.4", req, Policy{FailureAction: configuration.FailureActionBan})
	if err == nil {
		t.Fatal("ban on 500 expected an error")
	}
	if decision != nil {
		t.Fatalf("ban on 500 returned decision %#v", decision)
	}

	decision, err = client.Query("1.2.3.4", req, Policy{FailureAction: configuration.FailureActionPassthrough})
	if err != nil {
		t.Fatalf("passthrough on 500: %v", err)
	}
	if decision == nil || decision.Action != ActionAllow {
		t.Fatalf("passthrough on 500 want allow, got %#v", decision)
	}

	_, err = client.Query("1.2.3.4", req, Policy{FailureAction: configuration.FailureActionCaptcha})
	if !errors.Is(err, ErrFailureCaptcha) {
		t.Fatalf("captcha on 500 want ErrFailureCaptcha, got %v", err)
	}
}

// Test_appsecQuery_failureActionOnReverseProxyError proves HTTP 502/503/504 honor failure actions.
func Test_appsecQuery_failureActionOnReverseProxyError(t *testing.T) {
	for _, status := range []int{http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			appsecServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
				rw.WriteHeader(status)
			}))
			defer appsecServer.Close()
			appsecURL, _ := url.Parse(appsecServer.URL)
			client := newQueryClient(appsecURL, appsecServer.Client())
			req := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)

			decision, err := client.Query("1.2.3.4", req, Policy{FailureAction: configuration.FailureActionBan})
			if err == nil {
				t.Fatalf("ban on %d expected an error", status)
			}
			if decision != nil {
				t.Fatalf("ban on %d returned decision %#v", status, decision)
			}

			decision, err = client.Query("1.2.3.4", req, Policy{FailureAction: configuration.FailureActionPassthrough})
			if err != nil {
				t.Fatalf("passthrough on %d: %v", status, err)
			}
			if decision == nil || decision.Action != ActionAllow {
				t.Fatalf("passthrough on %d want allow, got %#v", status, decision)
			}

			_, err = client.Query("1.2.3.4", req, Policy{FailureAction: configuration.FailureActionCaptcha})
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

	_, err := client.Query("1.2.3.4", req, Policy{FailureAction: configuration.FailureActionBan})
	if err == nil {
		t.Fatal("ban on unreachable expected an error")
	}

	decision, err := client.Query("1.2.3.4", req, Policy{FailureAction: configuration.FailureActionPassthrough})
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

	decision, err := client.Query("1.2.3.4", req, Policy{FailureAction: configuration.FailureActionBan})
	if err == nil {
		t.Fatal("ban on response-body read error expected an error")
	}
	if !strings.Contains(err.Error(), "appsecQuery:readBody") {
		t.Fatalf("ban error %q want appsecQuery:readBody", err)
	}
	if decision != nil {
		t.Fatalf("ban on response-body read error returned decision %#v", decision)
	}

	decision, err = client.Query("1.2.3.4", req, Policy{FailureAction: configuration.FailureActionPassthrough})
	if err != nil {
		t.Fatalf("passthrough on response-body read error: %v", err)
	}
	if decision == nil || decision.Action != ActionAllow {
		t.Fatalf("passthrough on response-body read error want allow, got %#v", decision)
	}

	_, err = client.Query("1.2.3.4", req, Policy{FailureAction: configuration.FailureActionCaptcha})
	if !errors.Is(err, ErrFailureCaptcha) {
		t.Fatalf("captcha on response-body read error want ErrFailureCaptcha, got %v", err)
	}
}

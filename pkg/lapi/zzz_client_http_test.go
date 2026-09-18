package lapi

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	cache "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	logger "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

// newTestQueryClient builds a Client in mode whose crowdsecQuery reaches the mock LAPI/CAPI server.
func newTestQueryClient(t *testing.T, server *httptest.Server, mode string) *Client {
	t.Helper()
	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	cacheClient := &cache.Client{}
	cacheClient.New(logger.New("ERROR", ""), false, "", nil, "", "", "")
	client := &Client{
		crowdsecScheme:    serverURL.Scheme,
		crowdsecHost:      serverURL.Host,
		crowdsecPath:      "/",
		crowdsecMode:      mode,
		cacheClient:       cacheClient,
		log:               logger.New("ERROR", ""),
		pluginVersion:     "test",
		crowdsecMachineID: "machine",
		crowdsecPassword:  "password",
		crowdsecScenarios: []string{"scenario"},
	}
	attachTestTransport(client, server.Client(), "stale-token")
	return client
}

// testQueryRequest is one request the mock LAPI/CAPI saw.
type testQueryRequest struct {
	method string
	body   string
}

// TestCrowdsecQuery_TokenRenewalReplaysPostBody proves the alone-mode 401 retry reissues the same
// method and the same body instead of downgrading a POST to a bodyless GET.
func TestCrowdsecQuery_TokenRenewalReplaysPostBody(t *testing.T) {
	const payload = `{"payload":"keep-me"}`
	var mu sync.Mutex
	var seen []testQueryRequest
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if strings.Contains(req.URL.Path, crowdsecCapiLoginRoute) {
			if _, err := rw.Write([]byte(`{"code":200,"token":"fresh","expire":"later"}`)); err != nil {
				t.Errorf("login stub write: %v", err)
			}
			return
		}
		body, readErr := io.ReadAll(req.Body)
		if readErr != nil {
			t.Errorf("decision stub read: %v", readErr)
		}
		mu.Lock()
		seen = append(seen, testQueryRequest{method: req.Method, body: string(body)})
		isFirst := len(seen) == 1
		mu.Unlock()
		if isFirst {
			rw.WriteHeader(http.StatusUnauthorized)
			return
		}
		if _, err := rw.Write([]byte("[]")); err != nil {
			t.Errorf("decision stub write: %v", err)
		}
	}))
	defer server.Close()
	client := newTestQueryClient(t, server, configuration.AloneMode)

	if _, err := client.crowdsecQuery(server.URL+"/v1/decisions", []byte(payload)); err != nil {
		t.Fatalf("crowdsecQuery after token renewal: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 2 {
		t.Fatalf("decision requests=%d (%+v), want 2", len(seen), seen)
	}
	if seen[1].method != http.MethodPost {
		t.Fatalf("replay method %s, want POST", seen[1].method)
	}
	if seen[1].body != payload {
		t.Fatalf("replay body %q, want %q", seen[1].body, payload)
	}
}

// TestCrowdsecQuery_SecondUnauthorizedStopsRetrying proves a persistent 401 returns the status
// error instead of renewing the token again and recursing.
func TestCrowdsecQuery_SecondUnauthorizedStopsRetrying(t *testing.T) {
	var mu sync.Mutex
	var loginHits, decisionHits int
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		mu.Lock()
		if strings.Contains(req.URL.Path, crowdsecCapiLoginRoute) {
			loginHits++
		} else {
			decisionHits++
		}
		mu.Unlock()
		if strings.Contains(req.URL.Path, crowdsecCapiLoginRoute) {
			if _, err := rw.Write([]byte(`{"code":200,"token":"fresh","expire":"later"}`)); err != nil {
				t.Errorf("login stub write: %v", err)
			}
			return
		}
		rw.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()
	client := newTestQueryClient(t, server, configuration.AloneMode)

	_, err := client.crowdsecQuery(server.URL+"/v1/decisions", []byte(`{"payload":"keep-me"}`))
	if err == nil {
		t.Fatal("a persistent 401 must return an error")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Fatalf("persistent 401 error %q, want the status code", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if decisionHits != 2 {
		t.Fatalf("decision requests=%d, want 2 (one attempt plus one replay)", decisionHits)
	}
	if loginHits != 1 {
		t.Fatalf("token renewals=%d, want 1", loginHits)
	}
}

// TestGetToken_UnauthorizedLoginDoesNotRecurse proves a 401 on the CAPI login route returns instead
// of renewing a token by calling itself.
func TestGetToken_UnauthorizedLoginDoesNotRecurse(t *testing.T) {
	var mu sync.Mutex
	var loginHits int
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		loginHits++
		mu.Unlock()
		rw.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()
	client := newTestQueryClient(t, server, configuration.AloneMode)

	if err := client.getToken(); err == nil {
		t.Fatal("a 401 on the login route must return an error")
	}
	mu.Lock()
	defer mu.Unlock()
	if loginHits != 1 {
		t.Fatalf("login requests=%d, want 1", loginHits)
	}
}

// TestCrowdsecQuery_ReusesConnection proves every answered response is drained and closed, so the
// keep-alive slot survives 502/503/504 as well as 2xx and plain non-2xx.
func TestCrowdsecQuery_ReusesConnection(t *testing.T) {
	for _, status := range []int{
		http.StatusOK,
		http.StatusInternalServerError,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout,
	} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var mu sync.Mutex
			conns := map[string]bool{}
			server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				mu.Lock()
				conns[req.RemoteAddr] = true
				mu.Unlock()
				rw.WriteHeader(status)
				if _, err := rw.Write([]byte(`[]`)); err != nil {
					t.Errorf("lapi stub write: %v", err)
				}
			}))
			defer server.Close()
			client := newTestQueryClient(t, server, configuration.LiveMode)
			const calls = 10
			for range calls {
				_, _ = client.crowdsecQuery(server.URL+"/v1/decisions", nil)
			}
			mu.Lock()
			defer mu.Unlock()
			if len(conns) != 1 {
				t.Errorf("crowdsecQuery opened %d connections for %d calls, want 1 (response body not drained?)", len(conns), calls)
			}
		})
	}
}

// TestCrowdsecQuery_ReverseProxyStatusMessageNamesTheStatus proves the operator reads the status
// code that failed rather than a %w applied to a nil error.
func TestCrowdsecQuery_ReverseProxyStatusMessageNamesTheStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusServiceUnavailable)
		if _, err := rw.Write([]byte("unavailable")); err != nil {
			t.Errorf("lapi stub write: %v", err)
		}
	}))
	defer server.Close()
	client := newTestQueryClient(t, server, configuration.LiveMode)

	_, err := client.crowdsecQuery(server.URL+"/v1/decisions", nil)
	if err == nil {
		t.Fatal("503 must return an error")
	}
	if strings.Contains(err.Error(), "%!w(<nil>)") {
		t.Fatalf("reverse-proxy status message wraps a nil error: %s", err)
	}
	if !strings.Contains(err.Error(), "statusCode:503") {
		t.Fatalf("reverse-proxy status message %q must name the status code", err)
	}
	if !strings.Contains(err.Error(), "crowdsecQuery:unreachable") {
		t.Fatalf("reverse-proxy status message %q must keep the unreachable prefix", err)
	}
}

// TestCrowdsecQuery_TransportErrorWrapsItsCause proves the transport branch still wraps its error.
func TestCrowdsecQuery_TransportErrorWrapsItsCause(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
	}))
	deadURL := server.URL + "/v1/decisions"
	client := newTestQueryClient(t, server, configuration.LiveMode)
	server.Close()

	_, err := client.crowdsecQuery(deadURL, nil)
	if err == nil {
		t.Fatal("a closed LAPI must return an error")
	}
	if strings.Contains(err.Error(), "%!w(<nil>)") {
		t.Fatalf("transport error message wraps a nil error: %s", err)
	}
	if !strings.Contains(err.Error(), "crowdsecQuery:unreachable") {
		t.Fatalf("transport error message %q must keep the unreachable prefix", err)
	}
	if errors.Unwrap(err) == nil {
		t.Fatalf("transport error %q must wrap the transport cause", err)
	}
}

package lapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	logger "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

// newTestQueryClient builds a Client in mode whose crowdsecQuery reaches the mock LAPI/CAPI server.
func newTestQueryClient(t *testing.T, server *httptest.Server, mode string) *Client {
	t.Helper()
	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	client, _ := NewTestClient(logger.New("ERROR", ""))
	client.crowdsecScheme = serverURL.Scheme
	client.crowdsecHost = serverURL.Host
	client.crowdsecPath = "/"
	client.lapiMode = mode
	client.log = logger.New("ERROR", "")
	client.pluginVersion = "test"
	client.crowdsecMachineID = "machine"
	client.crowdsecPassword = "password"
	client.crowdsecScenarios = []string{"scenario"}
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

// TestGetToken_TwoXXBodyWithoutJSONCode proves a 2xx CAPI login body with token and no JSON code
// stores that token on the transport.
func TestGetToken_TwoXXBodyWithoutJSONCode(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if !strings.Contains(req.URL.Path, crowdsecCapiLoginRoute) {
			t.Errorf("unexpected path %s", req.URL.Path)
			rw.WriteHeader(http.StatusNotFound)
			return
		}
		if _, err := rw.Write([]byte(`{"token":"fresh","expire":"later"}`)); err != nil {
			t.Errorf("login stub write: %v", err)
		}
	}))
	defer server.Close()
	client := newTestQueryClient(t, server, configuration.AloneMode)

	if err := client.getToken(); err != nil {
		t.Fatalf("getToken after 2xx token-without-code: %v", err)
	}
	stored := client.currentTransport()
	if stored == nil {
		t.Fatal("stored transport is nil")
	}
	if stored.key != "fresh" {
		t.Fatalf("stored transport key %q, want fresh", stored.key)
	}
}

// TestGetToken_TwoXXEmptyTokenKeepsStatusCodeError proves a 2xx login body with an empty token
// still returns the existing getToken statusCode: error.
func TestGetToken_TwoXXEmptyTokenKeepsStatusCodeError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if !strings.Contains(req.URL.Path, crowdsecCapiLoginRoute) {
			t.Errorf("unexpected path %s", req.URL.Path)
			rw.WriteHeader(http.StatusNotFound)
			return
		}
		if _, err := rw.Write([]byte(`{"token":"","expire":"later"}`)); err != nil {
			t.Errorf("login stub write: %v", err)
		}
	}))
	defer server.Close()
	client := newTestQueryClient(t, server, configuration.AloneMode)

	err := client.getToken()
	if err == nil {
		t.Fatal("an empty token on 2xx must return an error")
	}
	if !strings.HasPrefix(err.Error(), "getToken statusCode:") {
		t.Fatalf("empty-token error %q, want prefix getToken statusCode:", err)
	}
	stored := client.currentTransport()
	if stored == nil {
		t.Fatal("stored transport is nil")
	}
	if stored.key != "stale-token" {
		t.Fatalf("stored transport key %q, want stale-token", stored.key)
	}
}

// testLoginBodyStub records the last watchers-login POST body.
type testLoginBodyStub struct {
	mu   sync.Mutex
	body []byte
}

// lastBody is a copy of the last recorded login POST body.
func (s *testLoginBodyStub) lastBody() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	copied := make([]byte, len(s.body))
	copy(copied, s.body)
	return copied
}

// handler records the request body and answers with a successful CAPI login token.
func (s *testLoginBodyStub) handler(t *testing.T) http.HandlerFunc {
	t.Helper()
	return func(rw http.ResponseWriter, req *http.Request) {
		body, readErr := io.ReadAll(req.Body)
		if readErr != nil {
			t.Errorf("login stub read: %v", readErr)
		}
		s.mu.Lock()
		s.body = body
		s.mu.Unlock()
		if _, err := rw.Write([]byte(`{"code":200,"token":"fresh","expire":"later"}`)); err != nil {
			t.Errorf("login stub write: %v", err)
		}
	}
}

// assertPostedLoginBodyMatches proves postedBody is JSON whose three login fields equal the credentials.
func assertPostedLoginBodyMatches(t *testing.T, postedBody []byte, machineID, password string, scenarios []string) {
	t.Helper()
	var posted map[string]json.RawMessage
	if err := json.Unmarshal(postedBody, &posted); err != nil {
		t.Fatalf("login body is not valid JSON: %v\n%s", err, postedBody)
	}
	if len(posted) != 3 {
		t.Fatalf("login body fields=%d (%v), want 3", len(posted), posted)
	}
	var postedMachineID, postedPassword string
	if err := json.Unmarshal(posted["machine_id"], &postedMachineID); err != nil {
		t.Fatalf("machine_id: %v", err)
	}
	if err := json.Unmarshal(posted["password"], &postedPassword); err != nil {
		t.Fatalf("password: %v", err)
	}
	if postedMachineID != machineID {
		t.Fatalf("machine_id %q, want %q", postedMachineID, machineID)
	}
	if postedPassword != password {
		t.Fatalf("password %q, want %q", postedPassword, password)
	}
	if scenarios == nil {
		if string(posted["scenarios"]) != "null" {
			t.Fatalf("scenarios %s, want null", posted["scenarios"])
		}
		return
	}
	var postedScenarios []string
	if err := json.Unmarshal(posted["scenarios"], &postedScenarios); err != nil {
		t.Fatalf("scenarios: %v", err)
	}
	if len(postedScenarios) != len(scenarios) {
		t.Fatalf("scenarios %q, want %q", postedScenarios, scenarios)
	}
	for i := range scenarios {
		if postedScenarios[i] != scenarios[i] {
			t.Fatalf("scenarios %q, want %q", postedScenarios, scenarios)
		}
	}
}

// TestGetToken_LoginBodyIsValidJSON proves the CAPI login POST is JSON that decodes back to the
// stored Client credentials, including quote, backslash, newline, and empty or nil scenario lists.
func TestGetToken_LoginBodyIsValidJSON(t *testing.T) {
	const metacharacters = "a\"b\\c\nd"
	cases := []struct {
		name      string
		machineID string
		password  string
		scenarios []string
	}{
		{
			name:      "metacharacters",
			machineID: metacharacters,
			password:  metacharacters,
			scenarios: []string{metacharacters},
		},
		{
			name:      "empty-scenarios",
			machineID: "machine",
			password:  "password",
			scenarios: []string{},
		},
		{
			name:      "nil-scenarios",
			machineID: "machine",
			password:  "password",
			scenarios: nil,
		},
	}
	for _, loginCase := range cases {
		t.Run(loginCase.name, func(t *testing.T) {
			loginStub := &testLoginBodyStub{}
			server := httptest.NewServer(loginStub.handler(t))
			defer server.Close()
			client := newTestQueryClient(t, server, configuration.AloneMode)
			client.crowdsecMachineID = loginCase.machineID
			client.crowdsecPassword = loginCase.password
			client.crowdsecScenarios = loginCase.scenarios

			if err := client.getToken(); err != nil {
				t.Fatalf("getToken: %v", err)
			}
			assertPostedLoginBodyMatches(t, loginStub.lastBody(), loginCase.machineID, loginCase.password, loginCase.scenarios)
		})
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

package httprule

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func mustNew(t *testing.T, rules []Rule) *Set {
	t.Helper()
	set, err := New(rules)
	if err != nil {
		t.Fatal(err)
	}
	return set
}

func TestNew_emptyListMatchesNothing(t *testing.T) {
	set := mustNew(t, nil)
	req := httptest.NewRequest(http.MethodGet, "http://example.com/health", nil)
	if set.Match(req) {
		t.Fatal("empty list must match nothing")
	}
	if set.Match(nil) {
		t.Fatal("nil request must not match")
	}
}

func TestNew_methodOnly(t *testing.T) {
	set := mustNew(t, []Rule{{Method: "^OPTIONS$"}})
	if !set.Match(httptest.NewRequest(http.MethodOptions, "http://example.com/", nil)) {
		t.Fatal("method-only must match OPTIONS")
	}
	if set.Match(httptest.NewRequest(http.MethodGet, "http://example.com/", nil)) {
		t.Fatal("method-only must not match GET")
	}
}

func TestNew_bangNegatesMethod(t *testing.T) {
	set := mustNew(t, []Rule{{Method: "!POST"}})
	if !set.Match(httptest.NewRequest(http.MethodGet, "http://example.com/", nil)) {
		t.Fatal("!POST must match GET")
	}
	if set.Match(httptest.NewRequest(http.MethodPost, "http://example.com/", nil)) {
		t.Fatal("!POST must not match POST")
	}
}

func TestNew_methodIsCaseSensitive(t *testing.T) {
	set := mustNew(t, []Rule{{Method: "^post$"}})
	if set.Match(httptest.NewRequest(http.MethodPost, "http://example.com/", nil)) {
		t.Fatal("POST must not match ^post$ unless the operator writes (?i)")
	}
}

func TestNew_rejectsDoubleBangAndEmptyNegation(t *testing.T) {
	if _, err := New([]Rule{{Method: "!!POST"}}); err == nil || !strings.Contains(err.Error(), "double negation") {
		t.Fatalf("!! must fail New, got %v", err)
	}
	if _, err := New([]Rule{{Method: "!"}}); err == nil || !strings.Contains(err.Error(), "empty negation") {
		t.Fatalf("! must fail New, got %v", err)
	}
}

func TestNew_rejectsFullyEmptyAndMatchEverythingMethod(t *testing.T) {
	if _, err := New([]Rule{{}}); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("{} must fail New, got %v", err)
	}
	if _, err := New([]Rule{{Method: ".*"}}); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("{method: .*} must fail New, got %v", err)
	}
}

func TestNew_rejectsInvalidRE2(t *testing.T) {
	if _, err := New([]Rule{{Path: "("}}); err == nil {
		t.Fatal("invalid path RE2 must fail New")
	}
	if _, err := New([]Rule{{Method: "("}}); err == nil {
		t.Fatal("invalid method RE2 must fail New")
	}
	if _, err := New([]Rule{{Headers: map[string]string{"X-Health": "("}}}); err == nil {
		t.Fatal("invalid header RE2 must fail New")
	}
	if _, err := New([]Rule{{Cookies: map[string]string{"session": "("}}}); err == nil {
		t.Fatal("invalid cookie RE2 must fail New")
	}
}

func TestMatch_methodAndPathAreAnd(t *testing.T) {
	set := mustNew(t, []Rule{{Method: "^GET$", Path: "^/healthz$"}})
	if set.Match(httptest.NewRequest(http.MethodGet, "http://example.com/other", nil)) {
		t.Fatal("GET /other must not match method+path AND")
	}
	if !set.Match(httptest.NewRequest(http.MethodGet, "http://example.com/healthz", nil)) {
		t.Fatal("GET /healthz must match method+path AND")
	}
	if set.Match(httptest.NewRequest(http.MethodPost, "http://example.com/healthz", nil)) {
		t.Fatal("POST /healthz must not match method+path AND")
	}
}

func TestMatch_unanchoredPath(t *testing.T) {
	set := mustNew(t, []Rule{{Path: "health"}})
	req := httptest.NewRequest(http.MethodGet, "http://example.com/unhealthy", nil)
	if !set.Match(req) {
		t.Fatal("unanchored health must match /unhealthy")
	}
}

func TestMatch_headerAndAndEmptyPresent(t *testing.T) {
	andSet := mustNew(t, []Rule{{Headers: map[string]string{"X-Health": "^ok$", "X-Role": "^probe$"}}})
	okOnly := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	okOnly.Header.Set("X-Health", "ok")
	if andSet.Match(okOnly) {
		t.Fatal("header AND must fail when X-Role is missing")
	}
	okAndRole := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	okAndRole.Header.Set("X-Health", "ok")
	okAndRole.Header.Set("X-Role", "probe")
	if !andSet.Match(okAndRole) {
		t.Fatal("header AND must match when both names hit")
	}

	presentSet := mustNew(t, []Rule{{Headers: map[string]string{"X-Health": ""}}})
	missing := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	if presentSet.Match(missing) {
		t.Fatal("empty header pattern must not match a missing header")
	}
	present := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	present.Header.Set("X-Health", "anything")
	if !presentSet.Match(present) {
		t.Fatal("empty header pattern must match a present header")
	}
}

func TestMatch_cookieNamesAreCaseSensitive(t *testing.T) {
	set := mustNew(t, []Rule{{Cookies: map[string]string{"session": "^[a-f0-9]+$"}}})
	wrongCase := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	wrongCase.AddCookie(&http.Cookie{Name: "Session", Value: "abc"})
	if set.Match(wrongCase) {
		t.Fatal("cookie Session must not match name session")
	}
	rightCase := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	rightCase.AddCookie(&http.Cookie{Name: "session", Value: "abc"})
	if !set.Match(rightCase) {
		t.Fatal("cookie session must match")
	}
}

func TestMatch_firstRuleWins(t *testing.T) {
	set := mustNew(t, []Rule{{Path: "^/a"}, {Path: "^/ab"}})
	req := httptest.NewRequest(http.MethodGet, "http://example.com/ab", nil)
	if !set.Match(req) {
		t.Fatal("first matching rule must win")
	}
}

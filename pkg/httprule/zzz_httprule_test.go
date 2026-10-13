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

func TestNew_rejectsInvalidRE2(t *testing.T) {
	if _, err := New([]Rule{{Method: "!!POST"}}); err == nil || !strings.Contains(err.Error(), "double negation") {
		t.Fatalf("!! must fail New, got %v", err)
	}
	if _, err := New([]Rule{{Method: "!"}}); err == nil || !strings.Contains(err.Error(), "empty negation") {
		t.Fatalf("! must fail New, got %v", err)
	}
	if _, err := New([]Rule{{}}); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("{} must fail New, got %v", err)
	}
	if _, err := New([]Rule{{Method: ".*"}}); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("{method: .*} must fail New, got %v", err)
	}

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
	if _, err := New([]Rule{{Host: "("}}); err == nil || !strings.Contains(err.Error(), "host") {
		t.Fatalf("invalid host RE2 must fail New naming host, got %v", err)
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

func TestNew_hostOnly(t *testing.T) {
	set := mustNew(t, []Rule{{Host: "^example.com$"}})
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	if !set.Match(req) {
		t.Fatal("host-only must match a bare example.com")
	}
}

func TestMatch_hostPortIsStripped(t *testing.T) {
	cases := []struct {
		name, host, rawURL string
	}{
		{name: "ipv4", host: "^example.com$", rawURL: "http://example.com:443/"},
		{name: "ipv6", host: "^::1$", rawURL: "http://[::1]:443/"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			set := mustNew(t, []Rule{{Host: tc.host}})
			req := httptest.NewRequest(http.MethodGet, tc.rawURL, nil)
			if !set.Match(req) {
				t.Fatalf("host must match after stripping the port from %s", tc.rawURL)
			}
		})
	}
}

func TestMatch_hostAndPathAreAnd(t *testing.T) {
	set := mustNew(t, []Rule{{Host: "^example.com$", Path: "^/healthz$"}})
	wrongPath := httptest.NewRequest(http.MethodGet, "http://example.com/other", nil)
	if set.Match(wrongPath) {
		t.Fatal("host+path AND must fail when the path misses")
	}
	ok := httptest.NewRequest(http.MethodGet, "http://example.com/healthz", nil)
	if !set.Match(ok) {
		t.Fatal("host+path AND must match example.com /healthz")
	}
}

func TestMatch_nonMatchingHostDoesNotBypass(t *testing.T) {
	set := mustNew(t, []Rule{{Host: "^probe.example$"}})
	req := httptest.NewRequest(http.MethodGet, "http://other.example/", nil)
	if set.Match(req) {
		t.Fatal("non-matching host must not match")
	}
}

func mustNewActionSet(t *testing.T, rules []ActionRule) *ActionSet {
	t.Helper()
	set, err := NewActionSet(rules)
	if err != nil {
		t.Fatal(err)
	}
	return set
}

func TestMatching_returnsEveryHitInOrder(t *testing.T) {
	set := mustNew(t, []Rule{{Path: "^/ab"}, {Path: "^/a"}, {Path: "^/ab"}})
	req := httptest.NewRequest(http.MethodGet, "http://example.com/ab", nil)
	got := set.Matching(req)
	if len(got) != 3 || got[0] != 0 || got[1] != 1 || got[2] != 2 {
		t.Fatalf("Matching=%v want [0 1 2]", got)
	}
	if !set.Match(req) {
		t.Fatal("Match dest first-wins must still be true")
	}
}

func TestMatching_emptyListAndNilRequest(t *testing.T) {
	set := mustNew(t, nil)
	req := httptest.NewRequest(http.MethodGet, "http://example.com/health", nil)
	if hits := set.Matching(req); hits != nil {
		t.Fatalf("empty list Matching=%v want nil", hits)
	}
	if hits := set.Matching(nil); hits != nil {
		t.Fatalf("nil request Matching=%v want nil", hits)
	}
	var nilSet *Set
	if hits := nilSet.Matching(req); hits != nil {
		t.Fatalf("nil set Matching=%v want nil", hits)
	}
}

func TestNewActionSet_emptyListMatchesNothing(t *testing.T) {
	set := mustNewActionSet(t, nil)
	req := httptest.NewRequest(http.MethodGet, "http://example.com/health", nil)
	if hits := set.Matching(req); len(hits) != 0 {
		t.Fatalf("empty ActionSet Matching=%v", hits)
	}
}

func TestNewActionSet_rejectsNameAndAction(t *testing.T) {
	tests := []struct {
		name    string
		rules   []ActionRule
		wantErr string
	}{
		{name: "empty name", rules: []ActionRule{{Action: []string{ActionBypass}, Rule: Rule{Path: "^/x$"}}}, wantErr: "name: empty"},
		{name: "colon in name", rules: []ActionRule{{Name: "a:b", Action: []string{ActionBypass}, Rule: Rule{Path: "^/x$"}}}, wantErr: "name: contains colon"},
		{name: "duplicate name", rules: []ActionRule{
			{Name: "healthz", Action: []string{ActionBypass}, Rule: Rule{Path: "^/a$"}},
			{Name: "healthz", Action: []string{ActionBypass}, Rule: Rule{Path: "^/b$"}},
		}, wantErr: "name: duplicate"},
		{name: "empty action", rules: []ActionRule{{Name: "x", Rule: Rule{Path: "^/x$"}}}, wantErr: "action: empty"},
		{name: "unknown token", rules: []ActionRule{{Name: "x", Action: []string{"pass"}, Rule: Rule{Path: "^/x$"}}}, wantErr: `action: unknown "pass"`},
		{name: "duplicate token", rules: []ActionRule{{Name: "x", Action: []string{ActionBypass, ActionBypass}, Rule: Rule{Path: "^/x$"}}}, wantErr: "action: duplicate"},
		{name: "ban with skip", rules: []ActionRule{{Name: "x", Action: []string{ActionBan, ActionBypass}, Rule: Rule{Path: "^/x$"}}}, wantErr: "action: ban must be alone"},
		{name: "ban with captcha", rules: []ActionRule{{Name: "x", Action: []string{ActionBan, ActionCaptcha}, Rule: Rule{Path: "^/x$"}}}, wantErr: "action: ban must be alone"},
		{name: "fully empty predicates", rules: []ActionRule{{Name: "x", Action: []string{ActionBypass}}}, wantErr: "empty"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewActionSet(tt.rules)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err=%v want %q", err, tt.wantErr)
			}
			if !strings.Contains(err.Error(), "rule 0:") && !strings.Contains(err.Error(), "rule 1:") {
				t.Fatalf("want index-prefixed error, got %v", err)
			}
		})
	}
}

func TestNewActionSet_zipsTokensWithMatching(t *testing.T) {
	set := mustNewActionSet(t, []ActionRule{
		{Name: "lapi", Action: []string{ActionBypassLapi}, Rule: Rule{Path: "^/ab"}},
		{Name: "appsec", Action: []string{ActionBypassAppsec}, Rule: Rule{Path: "^/ab"}},
		{Name: "other", Action: []string{ActionBan}, Rule: Rule{Path: "^/nope$"}},
	})
	req := httptest.NewRequest(http.MethodGet, "http://example.com/ab", nil)
	hits := set.Matching(req)
	if len(hits) != 2 || hits[0] != 0 || hits[1] != 1 {
		t.Fatalf("Matching=%v want [0 1]", hits)
	}
	if !set.SkipLapi(0) || set.SkipAppsec(0) || set.Ban(0) {
		t.Fatal("index 0 must be bypassLapi only")
	}
	if set.SkipLapi(1) || !set.SkipAppsec(1) {
		t.Fatal("index 1 must be bypassAppsec only")
	}
	if set.Name(0) != "lapi" || set.Name(1) != "appsec" {
		t.Fatalf("names %q %q", set.Name(0), set.Name(1))
	}
}

func TestActionSet_fold(t *testing.T) {
	var nilSet *ActionSet
	if got := nilSet.Fold(httptest.NewRequest(http.MethodGet, "http://example.com/", nil)); got != (ActionMatch{}) {
		t.Fatalf("nil set Fold=%+v", got)
	}
	set := mustNewActionSet(t, []ActionRule{
		{Name: "wide-captcha", Action: []string{ActionCaptcha}, Rule: Rule{Path: "^/a"}},
		{Name: "first-ban", Action: []string{ActionBan}, Rule: Rule{Path: "^/ab"}},
		{Name: "second-ban", Action: []string{ActionBan}, Rule: Rule{Path: "^/ab"}},
		{Name: "lapi", Action: []string{ActionBypassLapi}, Rule: Rule{Path: "^/ab"}},
		{Name: "appsec", Action: []string{ActionBypassAppsec}, Rule: Rule{Path: "^/ab"}},
		{Name: "narrow-captcha", Action: []string{ActionCaptcha, ActionBypass}, Rule: Rule{Path: "^/abc"}},
	})
	miss := set.Fold(httptest.NewRequest(http.MethodGet, "http://example.com/z", nil))
	if miss != (ActionMatch{}) {
		t.Fatalf("miss Fold=%+v", miss)
	}
	got := set.Fold(httptest.NewRequest(http.MethodGet, "http://example.com/abc", nil))
	want := ActionMatch{BanName: "first-ban", CaptchaName: "wide-captcha", SkipAppsec: true, SkipLapi: true}
	if got != want {
		t.Fatalf("Fold=%+v want %+v", got, want)
	}
}

func TestNewActionSet_bypassTokenSkipsBothLegs(t *testing.T) {
	set := mustNewActionSet(t, []ActionRule{
		{Name: "challenge-health", Action: []string{ActionCaptcha, ActionBypass}, Rule: Rule{Path: "^/healthz$"}},
	})
	req := httptest.NewRequest(http.MethodGet, "http://example.com/healthz", nil)
	hits := set.Matching(req)
	if len(hits) != 1 || hits[0] != 0 {
		t.Fatalf("Matching=%v want [0]", hits)
	}
	if !set.SkipLapi(0) || !set.SkipAppsec(0) || !set.Captcha(0) || set.Ban(0) {
		t.Fatal("bypass must skip both legs and keep captcha")
	}
}

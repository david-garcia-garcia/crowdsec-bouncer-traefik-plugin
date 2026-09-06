package captcha

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

// newTestClient builds a captcha Client with an isolated memory cache for tests.
func newTestClient(t *testing.T, validateURL string) (*Client, *cache.Client) {
	t.Helper()
	log := logger.New("ERROR", "")
	cacheClient := &cache.Client{}
	cacheClient.New(log, false, "", nil, "", "", "")
	client := &Client{}
	err := client.New(log, cacheClient, http.DefaultClient, configuration.CustomProvider, "http://js.test", "test-captcha", "test-response", validateURL, "site", "secret", "", "missing.html", 60)
	if err != nil {
		t.Fatal(err)
	}
	return client, cacheClient
}

// requestWithSessionCookie is a GET that carries crowdsec_captcha.
func requestWithSessionCookie(token string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
	return req
}

// TestCheckRequiresMatchingSessionCookie covers shared-IP, wrong cookie, other IP, and leftover IP-only keys.
func TestCheckRequiresMatchingSessionCookie(t *testing.T) {
	client, cacheClient := newTestClient(t, "http://validate.test")
	const remoteIP = "203.0.113.10"
	token := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	cacheClient.Set(sessionCacheKey(remoteIP, token), cache.CaptchaDoneValue, 60)
	cacheClient.Set(remoteIP+"_captcha", cache.CaptchaDoneValue, 60)

	if client.Check(httptest.NewRequest(http.MethodGet, "http://example.test/", nil), remoteIP) {
		t.Fatal("shared IP without cookie must be unsolved")
	}
	if !client.Check(requestWithSessionCookie(token), remoteIP) {
		t.Fatal("matching cookie on the same IP must be solved")
	}
	if client.Check(requestWithSessionCookie("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"), remoteIP) {
		t.Fatal("wrong cookie must be unsolved")
	}
	if client.Check(requestWithSessionCookie(token), "203.0.113.11") {
		t.Fatal("cookie copied to another IP must be unsolved")
	}
	if client.Check(nil, remoteIP) {
		t.Fatal("nil request must be unsolved")
	}
}

// TestServeHTTPSetsSessionCookieAndDoesNotKeyIPAlone checks Set-Cookie on solve and that IP-only grace is not written.
func TestServeHTTPSetsSessionCookieAndDoesNotKeyIPAlone(t *testing.T) {
	validate := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(rw, `{"success":true}`)
	}))
	t.Cleanup(validate.Close)

	client, cacheClient := newTestClient(t, validate.URL)
	form := url.Values{}
	form.Set("test-response", "provider-token")
	req := httptest.NewRequest(http.MethodPost, "http://example.test/page", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.TLS = &tls.ConnectionState{}
	recorder := httptest.NewRecorder()

	const remoteIP = "203.0.113.10"
	client.ServeHTTP(recorder, req, remoteIP)

	res := recorder.Result()
	if res.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want %d", res.StatusCode, http.StatusFound)
	}
	var session *http.Cookie
	for _, cookie := range res.Cookies() {
		if cookie.Name == sessionCookieName {
			session = cookie
			break
		}
	}
	if session == nil {
		t.Fatal("missing crowdsec_captcha Set-Cookie")
	}
	if !session.HttpOnly || session.Path != "/" || session.SameSite != http.SameSiteLaxMode || !session.Secure || session.MaxAge != 60 {
		t.Fatalf("cookie flags = %+v", session)
	}
	if _, err := cacheClient.Get(remoteIP + "_captcha"); err == nil {
		t.Fatal("IP-only grace key must not be written")
	}
	if !client.Check(requestWithSessionCookie(session.Value), remoteIP) {
		t.Fatal("issued cookie must pass Check")
	}
	peer := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	if client.Check(peer, remoteIP) {
		t.Fatal("peer on the same IP without cookie must not pass")
	}
}

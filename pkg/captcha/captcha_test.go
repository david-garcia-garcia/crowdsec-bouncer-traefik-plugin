package captcha

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"text/template"

	cache "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	logger "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

func testCaptchaClient(t *testing.T, validateURL, traceIDHeader string) *Client {
	t.Helper()
	tpl, err := template.New("captcha").Parse("trace:{{ .TraceID }}")
	if err != nil {
		t.Fatal(err)
	}
	cacheClient := &cache.Client{}
	cacheClient.New(logger.New("ERROR", ""), false, "", nil, "", "", "")
	return &Client{
		Valid:               true,
		siteKey:             "site",
		secretKey:           "secret",
		traceIDHeader:       traceIDHeader,
		template:            tpl,
		templateContentType: "text/html; charset=utf-8",
		cacheClient:         cacheClient,
		httpClient:          http.DefaultClient,
		log:                 logger.New("ERROR", ""),
		infoProvider: &infoProvider{
			js:       "js",
			key:      "k",
			response: "h-captcha-response",
			validate: validateURL,
		},
	}
}

func TestServeHTTPCaptchaHTMLTraceID(t *testing.T) {
	c := testCaptchaClient(t, "http://127.0.0.1:1/unused", "X-Trace-ID")
	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://example.com/foo", nil)
	c.ServeHTTP(rw, req, "1.2.3.4", "0102030405060708")
	if rw.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rw.Code)
	}
	if got := rw.Header().Get("X-Trace-ID"); got != "0102030405060708" {
		t.Errorf("header X-Trace-ID = %q, want generated id", got)
	}
	if body := rw.Body.String(); body != "trace:0102030405060708" {
		t.Errorf("body = %q", body)
	}
}

func TestServeHTTPSolvedCaptchaOmitsTraceID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"success":true}`)
	}))
	t.Cleanup(srv.Close)
	c := testCaptchaClient(t, srv.URL, "X-Trace-ID")
	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "http://example.com/foo", strings.NewReader("h-captcha-response=token"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	c.ServeHTTP(rw, req, "1.2.3.4", "0102030405060708")
	if rw.Code != http.StatusFound {
		t.Errorf("status = %d, want 302", rw.Code)
	}
	if got := rw.Header().Get("X-Trace-ID"); got != "" {
		t.Errorf("solved redirect X-Trace-ID = %q, want empty", got)
	}
}

func TestNewStoresTraceIDHeader(t *testing.T) {
	c := &Client{}
	err := c.New(logger.New("ERROR", ""), &cache.Client{}, http.DefaultClient, configuration.HcaptchaProvider, "", "", "", "", "site", "secret", "", "X-Trace-ID", "", 1)
	if err != nil {
		t.Fatal(err)
	}
	if c.traceIDHeader != "X-Trace-ID" {
		t.Errorf("traceIDHeader = %q", c.traceIDHeader)
	}
}

package captcha

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	cache "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
	configuration "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	logger "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

func newTestCustomClient(t *testing.T, js, challenge string) *Client {
	t.Helper()
	cacheClient := &cache.Client{}
	cacheClient.New(logger.New("INFO", ""), false, "", nil, "", "", "")
	client := &Client{}
	err := client.New(
		logger.New("INFO", ""),
		cacheClient,
		&http.Client{},
		configuration.CustomProvider,
		js,
		challenge,
		"wicketkeeper",
		"wicketkeeper_solution",
		"http://wicketkeeper:8080/v0/siteverify",
		"site",
		"secret",
		"",
		"testdata/captcha.html",
		1800,
	)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestCustomResourcePath(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{name: "absolute URL keeps path", raw: "http://captcha.localhost:8000/fast.js", want: "/fast.js"},
		{name: "path only", raw: "/v0/challenge", want: "/v0/challenge"},
		{name: "path with query uses path", raw: "/v0/challenge?difficulty=4", want: "/v0/challenge"},
		{name: "empty", raw: "", want: ""},
		{name: "no leading slash", raw: "fast.js", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := customResourcePath(tt.raw); got != tt.want {
				t.Errorf("customResourcePath(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

func TestIsCustomResourceRequest(t *testing.T) {
	client := newTestCustomClient(t, "http://captcha.localhost:8000/fast.js", "/v0/challenge")
	tests := []struct {
		name string
		path string
		raw  string
		want bool
	}{
		{name: "absolute JS URL matches browser path", path: "/fast.js", want: true},
		{name: "challenge query ignored", raw: "/v0/challenge?nonce=1", want: true},
		{name: "other path", path: "/foo", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://whoami.localhost/x", nil)
			if tt.raw != "" {
				req = httptest.NewRequest(http.MethodGet, "http://whoami.localhost"+tt.raw, nil)
			} else {
				req.URL.Path = tt.path
			}
			if got := client.IsCustomResourceRequest(req); got != tt.want {
				t.Errorf("IsCustomResourceRequest path=%q raw=%q = %v, want %v", tt.path, tt.raw, got, tt.want)
			}
		})
	}
}

func TestIsCustomResourceRequestNonCustom(t *testing.T) {
	cacheClient := &cache.Client{}
	cacheClient.New(logger.New("INFO", ""), false, "", nil, "", "", "")
	client := &Client{}
	if err := client.New(
		logger.New("INFO", ""),
		cacheClient,
		&http.Client{},
		configuration.HcaptchaProvider,
		"",
		"",
		"",
		"",
		"",
		"site",
		"secret",
		"",
		"testdata/captcha.html",
		1800,
	); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "https://hcaptcha.com/1/api.js", nil)
	req.URL.Path = "/1/api.js"
	if client.IsCustomResourceRequest(req) {
		t.Fatal("non-custom provider must not match CDN JS paths")
	}
}

func TestServeHTTPChallengeURL(t *testing.T) {
	client := newTestCustomClient(t, "/fast.js", "http://captcha.localhost:8000/v0/challenge")
	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://whoami.localhost/foo", nil)
	client.ServeHTTP(rw, req, "203.0.113.10")
	body := rw.Body.String()
	if !strings.Contains(body, "http://captcha.localhost:8000/v0/challenge") {
		t.Errorf("captcha HTML missing ChallengeURL, body=%q", body)
	}
}

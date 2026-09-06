package bouncer

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"text/template"
	"time"

	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/appsec"
	cache "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
	captcha "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/captcha"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/ip"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/lapi"
	logger "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(wd) == "bouncer" {
		return filepath.Clean(filepath.Join(wd, "..", ".."))
	}
	return wd
}

func testMemoryCache(t *testing.T) *cache.Client {
	t.Helper()
	c := &cache.Client{}
	c.New(logger.New("ERROR", ""), false, "", nil, "", "", "")
	return c
}

func testUnreachableCache(t *testing.T) *cache.Client {
	t.Helper()
	c := &cache.Client{}
	c.New(logger.New("ERROR", ""), true, "127.0.0.1:1", nil, "", "", "p")
	t.Cleanup(func() { c.Close() })
	return c
}

const testServeHTTPClientIP = "192.0.2.10"

func testServeHTTPRequest() *http.Request {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.RemoteAddr = testServeHTTPClientIP + ":12345"
	return req
}

func testBouncerForServeHTTP(t *testing.T, lapiClient *lapi.Client, next http.Handler) *Bouncer {
	t.Helper()
	if next == nil {
		next = http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Error("next handler should not be called")
		})
	}
	return &Bouncer{
		enabled:                 true,
		crowdsecMode:            configuration.StreamMode,
		lapiClient:              lapiClient,
		captchaClient:           &captcha.Client{},
		next:                    next,
		remediationStatusCode:   http.StatusForbidden,
		remediationCustomHeader: "X-Remediation",
		log:                     logger.New("ERROR", ""),
		serverPoolStrategy:      &ip.PoolStrategy{},
		clientPoolStrategy:      &ip.PoolStrategy{},
	}
}

func testValidCaptchaClient(t *testing.T, cacheClient *cache.Client) *captcha.Client {
	t.Helper()
	client := &captcha.Client{}
	err := client.New(
		logger.New("ERROR", ""),
		cacheClient,
		&http.Client{Timeout: time.Second},
		configuration.HcaptchaProvider,
		"", "", "", "",
		"site-key",
		"secret-key",
		"X-Remediation",
		filepath.Join(repoRoot(t), "captcha.html"),
		60,
	)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestNew_propagatesCheckerAndTemplateErrors(t *testing.T) {
	t.Run("invalid forwarded headers CIDR", func(t *testing.T) {
		cfg := &configuration.Config{
			ForwardedHeadersTrustedIPs: []string{"not-a-cidr"},
		}
		_, err := New(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), "t", cfg, lapi.NewTestServeHTTPLapiClient(lapi.TestServeHTTPLapiOptions{}), nil, logger.New("ERROR", ""))
		if err == nil {
			t.Fatal("expected checker error")
		}
	})
	t.Run("missing ban template", func(t *testing.T) {
		cfg := &configuration.Config{
			BanFilePath: filepath.Join(t.TempDir(), "missing-ban.html"),
		}
		_, err := New(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), "t", cfg, lapi.NewTestServeHTTPLapiClient(lapi.TestServeHTTPLapiOptions{}), nil, logger.New("ERROR", ""))
		if err == nil {
			t.Fatal("expected ban template error")
		}
	})
}

func TestNew_appsecModeInitializesCaptchaForFailureAction(t *testing.T) {
	cfg := &configuration.Config{
		CrowdsecMode:                configuration.AppsecMode,
		CrowdsecAppsecFailureAction: configuration.FailureActionCaptcha,
		CaptchaProvider:             configuration.HcaptchaProvider,
		CaptchaSiteKey:              "site-key",
		CaptchaSecretKey:            "secret-key",
		CaptchaFilePath:             filepath.Join(repoRoot(t), "captcha.html"),
		Enabled:                     true,
	}
	handler, err := New(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), "appsec", cfg, lapi.NewTestServeHTTPLapiClient(lapi.TestServeHTTPLapiOptions{}), nil, logger.New("ERROR", ""))
	if err != nil {
		t.Fatal(err)
	}
	b, ok := handler.(*Bouncer)
	if !ok {
		t.Fatal("expected *Bouncer handler")
	}
	if !b.captchaClient.Valid {
		t.Fatal("appsec failure-action captcha must initialize captcha client")
	}
}

func TestNew_appsecModeSkipsCaptchaWhenNotNeeded(t *testing.T) {
	cfg := &configuration.Config{
		CrowdsecMode:                configuration.AppsecMode,
		CrowdsecAppsecFailureAction: configuration.FailureActionBan,
		Enabled:                     true,
	}
	handler, err := New(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), "appsec", cfg, lapi.NewTestServeHTTPLapiClient(lapi.TestServeHTTPLapiOptions{}), nil, logger.New("ERROR", ""))
	if err != nil {
		t.Fatal(err)
	}
	b, ok := handler.(*Bouncer)
	if !ok {
		t.Fatal("expected *Bouncer handler")
	}
	if b.captchaClient.Valid {
		t.Fatal("appsec ban failure action must not initialize captcha")
	}
}

func TestServeHTTP_cacheHitBan(t *testing.T) {
	cacheClient := testMemoryCache(t)
	cacheClient.Set("192.0.2.10", cache.BannedValue, 60)
	lapiClient := lapi.NewTestServeHTTPLapiClient(lapi.TestServeHTTPLapiOptions{
		Mode:          configuration.StreamMode,
		StreamHealthy: true,
		CacheClient:   cacheClient,
	})
	b := testBouncerForServeHTTP(t, lapiClient, nil)
	recorder := httptest.NewRecorder()
	b.ServeHTTP(recorder, testServeHTTPRequest())
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("cache ban want 403, got %d", recorder.Code)
	}
	if got := recorder.Header().Get("X-Remediation"); got != "ban" {
		t.Fatalf("want ban remediation, got %q", got)
	}
}

func TestServeHTTP_cacheHitCaptcha(t *testing.T) {
	cacheClient := testMemoryCache(t)
	cacheClient.Set("192.0.2.10", cache.CaptchaValue, 60)
	lapiClient := lapi.NewTestServeHTTPLapiClient(lapi.TestServeHTTPLapiOptions{
		Mode:          configuration.StreamMode,
		StreamHealthy: true,
		CacheClient:   cacheClient,
	})
	b := testBouncerForServeHTTP(t, lapiClient, nil)
	b.captchaClient = testValidCaptchaClient(t, cacheClient)
	recorder := httptest.NewRecorder()
	b.ServeHTTP(recorder, testServeHTTPRequest())
	if recorder.Code != http.StatusOK {
		t.Fatalf("captcha want 200, got %d", recorder.Code)
	}
	if got := recorder.Header().Get("X-Remediation"); got != "captcha" {
		t.Fatalf("want captcha remediation, got %q", got)
	}
}

func TestServeHTTP_streamUnhealthyFailureActions(t *testing.T) {
	t.Run("ban", func(t *testing.T) {
		lapiClient := lapi.NewTestServeHTTPLapiClient(lapi.TestServeHTTPLapiOptions{
			Mode:          configuration.StreamMode,
			FailureAction: configuration.FailureActionBan,
			StreamHealthy: false,
			CacheClient:   testMemoryCache(t),
		})
		b := testBouncerForServeHTTP(t, lapiClient, nil)
		recorder := httptest.NewRecorder()
		b.ServeHTTP(recorder, testServeHTTPRequest())
		if recorder.Code != http.StatusForbidden {
			t.Fatalf("stream unhealthy ban want 403, got %d", recorder.Code)
		}
	})
	t.Run("passthrough", func(t *testing.T) {
		nextCalled := false
		lapiClient := lapi.NewTestServeHTTPLapiClient(lapi.TestServeHTTPLapiOptions{
			Mode:          configuration.StreamMode,
			FailureAction: configuration.FailureActionPassthrough,
			StreamHealthy: false,
			CacheClient:   testMemoryCache(t),
		})
		b := testBouncerForServeHTTP(t, lapiClient, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			nextCalled = true
		}))
		b.ServeHTTP(httptest.NewRecorder(), testServeHTTPRequest())
		if !nextCalled {
			t.Fatal("stream unhealthy passthrough should call next")
		}
	})
	t.Run("captcha", func(t *testing.T) {
		cacheClient := testMemoryCache(t)
		lapiClient := lapi.NewTestServeHTTPLapiClient(lapi.TestServeHTTPLapiOptions{
			Mode:          configuration.StreamMode,
			FailureAction: configuration.FailureActionCaptcha,
			StreamHealthy: false,
			CacheClient:   cacheClient,
		})
		b := testBouncerForServeHTTP(t, lapiClient, nil)
		b.captchaClient = testValidCaptchaClient(t, cacheClient)
		recorder := httptest.NewRecorder()
		b.ServeHTTP(recorder, testServeHTTPRequest())
		if recorder.Code != http.StatusOK {
			t.Fatalf("stream unhealthy captcha want 200, got %d", recorder.Code)
		}
		if got := recorder.Header().Get("X-Remediation"); got != "captcha" {
			t.Fatalf("want captcha remediation, got %q", got)
		}
	})
}

func TestServeHTTP_redisUnreachable(t *testing.T) {
	t.Run("block bans", func(t *testing.T) {
		lapiClient := lapi.NewTestServeHTTPLapiClient(lapi.TestServeHTTPLapiOptions{
			Mode:                  configuration.StreamMode,
			StreamHealthy:         true,
			RedisUnreachableBlock: true,
			CacheClient:           testUnreachableCache(t),
		})
		b := testBouncerForServeHTTP(t, lapiClient, nil)
		recorder := httptest.NewRecorder()
		b.ServeHTTP(recorder, testServeHTTPRequest())
		if recorder.Code != http.StatusForbidden {
			t.Fatalf("redis unreachable block want 403, got %d", recorder.Code)
		}
	})
	t.Run("passthrough calls next", func(t *testing.T) {
		nextCalled := false
		lapiClient := lapi.NewTestServeHTTPLapiClient(lapi.TestServeHTTPLapiOptions{
			Mode:                  configuration.StreamMode,
			StreamHealthy:         true,
			RedisUnreachableBlock: false,
			CacheClient:           testUnreachableCache(t),
		})
		b := testBouncerForServeHTTP(t, lapiClient, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			nextCalled = true
		}))
		b.ServeHTTP(httptest.NewRecorder(), testServeHTTPRequest())
		if !nextCalled {
			t.Fatal("redis unreachable passthrough should call next")
		}
	})
}

func TestServeHTTP_getRemoteIPFailClose(t *testing.T) {
	b := testBouncerForServeHTTP(t, lapi.NewTestServeHTTPLapiClient(lapi.TestServeHTTPLapiOptions{
		Mode:          configuration.StreamMode,
		StreamHealthy: true,
		CacheClient:   testMemoryCache(t),
	}), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("next handler should not be called on IP extraction failure")
	}))
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.RemoteAddr = "not-a-valid-hostport"
	recorder := httptest.NewRecorder()
	b.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("invalid RemoteAddr want 403, got %d", recorder.Code)
	}
}

func TestHandleRemediationServeHTTP(t *testing.T) {
	cacheClient := testMemoryCache(t)
	captchaClient := testValidCaptchaClient(t, cacheClient)
	banTemplate, _ := template.New("ban").Parse("<html>ban</html>")

	tests := []struct {
		name            string
		method          string
		remediation     string
		captchaValid    bool
		captchaPassed   bool
		wantStatus      int
		wantRemediation string
		wantNext        bool
	}{
		{name: "GET captcha serves page", method: http.MethodGet, remediation: cache.CaptchaValue, captchaValid: true, wantStatus: http.StatusOK, wantRemediation: "captcha"},
		{name: "HEAD captcha bans", method: http.MethodHead, remediation: cache.CaptchaValue, captchaValid: true, wantStatus: http.StatusForbidden, wantRemediation: "ban"},
		{name: "invalid captcha client bans", method: http.MethodGet, remediation: cache.CaptchaValue, captchaValid: false, wantStatus: http.StatusForbidden, wantRemediation: "ban"},
		{name: "captcha grace passes", method: http.MethodGet, remediation: cache.CaptchaValue, captchaValid: true, captchaPassed: true, wantNext: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nextCalled := false
			b := &Bouncer{
				next: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
					nextCalled = true
				}),
				remediationStatusCode:   http.StatusForbidden,
				remediationCustomHeader: "X-Remediation",
				banTemplate:             banTemplate,
				banTemplateContentType:  "text/html",
				log:                     logger.New("ERROR", ""),
			}
			if tt.captchaValid {
				b.captchaClient = captchaClient
			} else {
				b.captchaClient = &captcha.Client{}
			}
			if tt.captchaPassed {
				cacheClient.Set("192.0.2.10_captcha", cache.CaptchaDoneValue, 60)
			} else {
				cacheClient.Delete("192.0.2.10_captcha")
			}
			recorder := httptest.NewRecorder()
			req := &http.Request{Method: tt.method, URL: &url.URL{Path: "/"}}
			b.handleRemediationServeHTTP(recorder, testClientRequest(req, "192.0.2.10"), tt.remediation, "test")
			if tt.wantNext {
				if !nextCalled {
					t.Fatal("expected next handler")
				}
				return
			}
			if nextCalled {
				t.Fatal("next handler should not be called")
			}
			if recorder.Code != tt.wantStatus {
				t.Fatalf("want status %d, got %d", tt.wantStatus, recorder.Code)
			}
			if got := recorder.Header().Get("X-Remediation"); got != tt.wantRemediation {
				t.Fatalf("want remediation %q, got %q", tt.wantRemediation, got)
			}
		})
	}
}

func TestApplyLapiFailureAction_captcha(t *testing.T) {
	cacheClient := testMemoryCache(t)
	b := &Bouncer{
		next: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Error("next handler should not be called")
		}),
		remediationStatusCode:   http.StatusForbidden,
		remediationCustomHeader: "X-Remediation",
		captchaClient:           testValidCaptchaClient(t, cacheClient),
		log:                     logger.New("ERROR", ""),
		lapiClient:              lapi.NewTestLapiFailureActionClient(configuration.FailureActionCaptcha),
	}
	recorder := httptest.NewRecorder()
	b.applyLapiFailureAction(recorder, testClientRequest(httptest.NewRequest(http.MethodGet, "http://example.com/", nil), "192.0.2.10"), configuration.ReasonTECH, lapi.OriginPluginTechStreamFail)
	if recorder.Code != http.StatusOK {
		t.Fatalf("failure-action captcha want 200, got %d", recorder.Code)
	}
	if got := recorder.Header().Get("X-Remediation"); got != "captcha" {
		t.Fatalf("want captcha remediation, got %q", got)
	}
}

func TestHandleNextServeHTTP_appsecFailureCaptcha(t *testing.T) {
	appsecServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer appsecServer.Close()
	appsecURL, err := url.Parse(appsecServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	cacheClient := testMemoryCache(t)
	b := &Bouncer{
		next: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Error("next handler should not be called")
		}),
		appsecEnabled:           true,
		appsecFailureAction:     configuration.FailureActionCaptcha,
		captchaClient:           testValidCaptchaClient(t, cacheClient),
		remediationCustomHeader: "X-Remediation",
		log:                     logger.New("ERROR", ""),
		appsecClient:            appsec.NewTestClient(appsecURL, appsecServer.Client(), logger.New("ERROR", "")),
	}
	recorder := httptest.NewRecorder()
	b.handleNextServeHTTP(recorder, testClientRequest(httptest.NewRequest(http.MethodGet, "http://example.com/protected", nil), "192.0.2.10"))
	if recorder.Code != http.StatusOK {
		t.Fatalf("appsec failure captcha want 200, got %d", recorder.Code)
	}
	if got := recorder.Header().Get("X-Remediation"); got != "captcha" {
		t.Fatalf("want captcha remediation, got %q", got)
	}
}

package captcha

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	cache "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	logger "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

// recordedSiteverify holds the last siteverify request the test server saw.
type recordedSiteverify struct {
	contentType string
	formSecret  string
	formToken   string
	jsonSecret  string
	jsonToken   string
	calls       int
}

// newTestCaptchaClient builds a Client for Validate tests.
func newTestCaptchaClient(t *testing.T, provider, responseField, validateURL, validateBody string) *Client {
	t.Helper()
	cacheClient := &cache.Client{}
	cacheClient.New(logger.New("ERROR", ""), false, "", nil, "", "", "")
	client := &Client{}
	err := client.New(
		logger.New("ERROR", ""),
		cacheClient,
		http.DefaultClient,
		provider,
		"http://js.example/widget.js",
		"cap-widget",
		responseField,
		validateURL,
		validateBody,
		"site-key",
		"secret-key",
		"",
		"",
		1800,
	)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

// newSiteverifyServer records the siteverify request encoding.
func newSiteverifyServer(t *testing.T, rec *recordedSiteverify) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rec.calls++
		rec.contentType = req.Header.Get("Content-Type")
		body, err := io.ReadAll(req.Body)
		if err != nil {
			t.Errorf("read siteverify body: %v", err)
			http.Error(rw, "read", http.StatusBadRequest)
			return
		}
		if strings.Contains(rec.contentType, "application/json") {
			var posted siteverifyRequest
			if err := json.Unmarshal(body, &posted); err != nil {
				t.Errorf("json siteverify body: %v", err)
			}
			rec.jsonSecret = posted.Secret
			rec.jsonToken = posted.Response
		} else {
			form, err := url.ParseQuery(string(body))
			if err != nil {
				t.Errorf("form siteverify body: %v", err)
			}
			rec.formSecret = form.Get("secret")
			rec.formToken = form.Get("response")
		}
		rw.Header().Set("Content-Type", "application/json")
		_, _ = rw.Write([]byte(`{"success":true}`))
	}))
}

// newBrowserPost is a browser captcha form POST.
func newBrowserPost(responseField, token string) *http.Request {
	form := url.Values{}
	form.Set(responseField, token)
	req := httptest.NewRequest(http.MethodPost, "http://bouncer.example/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

func TestValidate_customJSONPostsJSONBody(t *testing.T) {
	rec := &recordedSiteverify{}
	server := newSiteverifyServer(t, rec)
	defer server.Close()
	client := newTestCaptchaClient(t, configuration.CustomProvider, "cap-token", server.URL, configuration.CaptchaValidateBodyJSON)
	ok, err := client.Validate(newBrowserPost("cap-token", "tok-1"))
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected success")
	}
	if rec.calls != 1 {
		t.Fatalf("calls=%d", rec.calls)
	}
	if !strings.Contains(rec.contentType, "application/json") {
		t.Fatalf("content-type=%q", rec.contentType)
	}
	if rec.jsonSecret != "secret-key" || rec.jsonToken != "tok-1" {
		t.Fatalf("json secret=%q token=%q", rec.jsonSecret, rec.jsonToken)
	}
	if rec.formSecret != "" || rec.formToken != "" {
		t.Fatal("form fields must stay empty on json verify")
	}
}

func TestValidate_customFormPostsURLEncoded(t *testing.T) {
	rec := &recordedSiteverify{}
	server := newSiteverifyServer(t, rec)
	defer server.Close()
	client := newTestCaptchaClient(t, configuration.CustomProvider, "wicketkeeper_solution", server.URL, configuration.CaptchaValidateBodyForm)
	ok, err := client.Validate(newBrowserPost("wicketkeeper_solution", "tok-2"))
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected success")
	}
	if !strings.Contains(rec.contentType, "application/x-www-form-urlencoded") {
		t.Fatalf("content-type=%q", rec.contentType)
	}
	if rec.formSecret != "secret-key" || rec.formToken != "tok-2" {
		t.Fatalf("form secret=%q token=%q", rec.formSecret, rec.formToken)
	}
}

func TestValidate_customEmptyBodyPostsURLEncoded(t *testing.T) {
	rec := &recordedSiteverify{}
	server := newSiteverifyServer(t, rec)
	defer server.Close()
	client := newTestCaptchaClient(t, configuration.CustomProvider, "cap-token", server.URL, "")
	ok, err := client.Validate(newBrowserPost("cap-token", "tok-3"))
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected success")
	}
	if rec.formSecret != "secret-key" || rec.formToken != "tok-3" {
		t.Fatalf("form secret=%q token=%q", rec.formSecret, rec.formToken)
	}
}

func TestNew_hcaptchaIgnoresJSONBody(t *testing.T) {
	client := newTestCaptchaClient(t, configuration.HcaptchaProvider, "h-captcha-response", "http://unused.example/siteverify", configuration.CaptchaValidateBodyJSON)
	if client.infoProvider.validateBody != "" {
		t.Fatalf("built-in validateBody=%q, want empty (form)", client.infoProvider.validateBody)
	}
}

func TestValidate_nonPostSkipsSiteverify(t *testing.T) {
	rec := &recordedSiteverify{}
	server := newSiteverifyServer(t, rec)
	defer server.Close()
	client := newTestCaptchaClient(t, configuration.CustomProvider, "cap-token", server.URL, configuration.CaptchaValidateBodyJSON)
	ok, err := client.Validate(httptest.NewRequest(http.MethodGet, "http://bouncer.example/", nil))
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("GET must not validate")
	}
	if rec.calls != 0 {
		t.Fatalf("calls=%d", rec.calls)
	}
}

func TestValidate_missingTokenSkipsSiteverify(t *testing.T) {
	rec := &recordedSiteverify{}
	server := newSiteverifyServer(t, rec)
	defer server.Close()
	client := newTestCaptchaClient(t, configuration.CustomProvider, "cap-token", server.URL, configuration.CaptchaValidateBodyJSON)
	ok, err := client.Validate(newBrowserPost("other-field", "tok"))
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("missing token must not validate")
	}
	if rec.calls != 0 {
		t.Fatalf("calls=%d", rec.calls)
	}
}

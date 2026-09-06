// Package captcha implements utility for captcha management.
package captcha

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"text/template"

	cache "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
	configuration "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/configuration"
)

// Client Captcha client.
type Client struct {
	Valid                   bool
	siteKey                 string
	secretKey               string
	remediationCustomHeader string
	gracePeriodSeconds      int64
	templateContentType     string
	template                *template.Template
	cacheClient             *cache.Client
	httpClient              *http.Client
	log                     *slog.Logger
	infoProvider            *infoProvider
}

// Information for self-hosted provider.
type infoProvider struct {
	js       string
	key      string
	response string
	validate string
}

//nolint:gochecknoglobals
var infoProviders = map[string]*infoProvider{
	configuration.HcaptchaProvider: {
		js:       "https://hcaptcha.com/1/api.js",
		key:      "h-captcha",
		response: "h-captcha-response",
		validate: "https://api.hcaptcha.com/siteverify",
	},
	configuration.RecaptchaProvider: {
		js:       "https://www.google.com/recaptcha/api.js",
		key:      "g-recaptcha",
		response: "g-recaptcha-response",
		validate: "https://www.google.com/recaptcha/api/siteverify",
	},
	configuration.TurnstileProvider: {
		js:       "https://challenges.cloudflare.com/turnstile/v0/api.js",
		key:      "cf-turnstile",
		response: "cf-turnstile-response",
		validate: "https://challenges.cloudflare.com/turnstile/v0/siteverify",
	},
}

// New Initialize captcha client.
func (c *Client) New(log *slog.Logger, cacheClient *cache.Client, httpClient *http.Client, provider, js, key, response, validate, siteKey, secretKey, remediationCustomHeader, captchaTemplatePath string, gracePeriodSeconds int64) error {
	c.Valid = provider != ""
	if !c.Valid {
		return nil
	}
	var info *infoProvider
	if provider == configuration.CustomProvider {
		info = &infoProvider{js: js, key: key, response: response, validate: validate}
	} else {
		info = infoProviders[provider]
	}
	c.infoProvider = info
	c.siteKey = siteKey
	c.secretKey = secretKey
	c.remediationCustomHeader = remediationCustomHeader
	template, contentType, _ := configuration.GetTemplate(captchaTemplatePath)
	c.template = template
	c.templateContentType = contentType
	c.gracePeriodSeconds = gracePeriodSeconds
	c.log = log
	c.httpClient = httpClient
	c.cacheClient = cacheClient
	return nil
}

// ServeHTTP Handle captcha html page or validation.
func (c *Client) ServeHTTP(rw http.ResponseWriter, r *http.Request, remoteIP string) {
	valid, err := c.Validate(r)
	if err != nil {
		c.log.Info("captcha:ServeHTTP:validate " + err.Error())
		rw.WriteHeader(http.StatusBadRequest)
		return
	}
	if valid {
		c.log.Debug("captcha:ServeHTTP captcha:valid")
		c.cacheClient.Set(remoteIP+"_captcha", cache.CaptchaDoneValue, c.gracePeriodSeconds)
		c.WriteSolvedRedirect(rw, r)
		return
	}
	rw.Header().Set("Content-Type", c.templateContentType)
	if c.remediationCustomHeader != "" {
		rw.Header().Set(c.remediationCustomHeader, "captcha")
	}
	rw.WriteHeader(http.StatusOK)
	err = c.template.Execute(rw, map[string]string{
		"SiteKey":     c.siteKey,
		"FrontendJS":  c.infoProvider.js,
		"FrontendKey": c.infoProvider.key,
	})
	if err != nil {
		c.log.Info("captcha:ServeHTTP captchaTemplateServe " + err.Error())
	}
}

// Check Verify if the captcha is already done.
func (c *Client) Check(remoteIP string) bool {
	value, _ := c.cacheClient.Get(remoteIP + "_captcha")
	passed := value == cache.CaptchaDoneValue
	c.log.Debug(fmt.Sprintf("captcha:Check ip:%s pass:%v", remoteIP, passed))
	return passed
}

// WriteSolvedRedirect writes the 302 used after a successful captcha verify.
func (c *Client) WriteSolvedRedirect(rw http.ResponseWriter, r *http.Request) {
	if c.remediationCustomHeader != "" {
		rw.Header().Set(c.remediationCustomHeader, "solved-captcha")
	}
	http.Redirect(rw, r, r.URL.String(), http.StatusFound)
}

// IsCaptchaFormPost reports whether r is a POST that carries the configured provider response field.
// When the field is absent, Body is restored so origin can still read the POST.
func (c *Client) IsCaptchaFormPost(r *http.Request) bool {
	if r == nil || r.Method != http.MethodPost || c.infoProvider == nil {
		return false
	}
	field := c.infoProvider.response
	if field == "" {
		return false
	}

	// Already-parsed POST form: do not reread Body.
	if r.PostForm != nil {
		return r.PostForm.Get(field) != ""
	}

	// Known-large origin POST: do not buffer it to look for a captcha token.
	if r.ContentLength > captchaFormMaxBytes {
		return false
	}

	raw, err := readAndRestoreBody(r)
	if err != nil {
		return false
	}
	if raw == nil {
		return false
	}
	return providerResponseValue(r.Header.Get("Content-Type"), raw, field) != ""
}

// captchaFormMaxBytes is the largest POST parsed as a captcha form.
// Provider tokens are small; larger bodies are origin forms and must not be fully buffered here.
const captchaFormMaxBytes = 64 << 10

// readAndRestoreBody copies r.Body up to captchaFormMaxBytes and puts a readable copy back on r.
func readAndRestoreBody(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, captchaFormMaxBytes+1))
	if err != nil {
		_ = r.Body.Close()
		r.Body = io.NopCloser(bytes.NewReader(raw))
		return nil, err
	}
	if len(raw) > captchaFormMaxBytes {
		// Over the captcha-form cap: restore peeked bytes in front of the unread remainder.
		r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(raw), r.Body))
		return nil, nil
	}
	_ = r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(raw))
	r.ContentLength = int64(len(raw))
	return raw, nil
}

// providerResponseValue returns the named form field from a urlencoded or multipart body.
func providerResponseValue(contentType string, raw []byte, field string) string {
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil || mediaType == "" {
		mediaType = "application/x-www-form-urlencoded"
	}
	switch mediaType {
	case "application/x-www-form-urlencoded":
		values, parseErr := url.ParseQuery(string(raw))
		if parseErr != nil {
			return ""
		}
		return values.Get(field)
	case "multipart/form-data":
		boundary := params["boundary"]
		if boundary == "" {
			return ""
		}
		form, readErr := multipart.NewReader(bytes.NewReader(raw), boundary).ReadForm(10 << 20)
		if readErr != nil {
			return ""
		}
		defer func() { _ = form.RemoveAll() }()
		values := form.Value[field]
		if len(values) == 0 {
			return ""
		}
		return values[0]
	default:
		return ""
	}
}

type responseProvider struct {
	Success bool `json:"success"`
}

// Validate Verify the captcha from provider API.
func (c *Client) Validate(r *http.Request) (bool, error) {
	if r.Method != http.MethodPost {
		c.log.Debug("captcha:Validate invalid method: " + r.Method)
		return false, nil
	}
	var response = r.FormValue(c.infoProvider.response)
	if response == "" {
		c.log.Debug("captcha:Validate no captcha response found in request")
		return false, nil
	}
	var body = url.Values{}
	body.Add("secret", c.secretKey)
	body.Add("response", response)
	res, err := c.httpClient.PostForm(c.infoProvider.validate, body)
	if err != nil {
		return false, err
	}
	defer func() {
		if err = res.Body.Close(); err != nil {
			c.log.Error("captcha:Validate " + err.Error())
		}
	}()
	if !strings.Contains(res.Header.Get("Content-Type"), "application/json") {
		c.log.Debug("captcha:Validate responseType:noJson")
		return false, nil
	}
	var captchaResponse responseProvider
	err = json.NewDecoder(res.Body).Decode(&captchaResponse)
	if err != nil {
		return false, err
	}
	c.log.Debug(fmt.Sprintf("captcha:Validate success:%v", captchaResponse.Success))
	return captchaResponse.Success, nil
}

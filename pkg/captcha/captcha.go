// Package captcha implements utility for captcha management.
package captcha

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"text/template"
	"time"

	configuration "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/configuration"
)

// Client Captcha client.
type Client struct {
	Valid                   bool
	siteKey                 string
	secretKey               string
	gateSecret              []byte
	gateBindIP              bool
	remediationCustomHeader string
	gracePeriodSeconds      int64
	templateContentType     string
	template                *template.Template
	httpClient              *http.Client
	log                     *slog.Logger
	infoProvider            *infoProvider
	customResourcePaths     []string
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
func (c *Client) New(log *slog.Logger, httpClient *http.Client, provider, js, challengeURL, key, response, validate, siteKey, secretKey, gateSecret string, gateBindIP bool, remediationCustomHeader, captchaTemplatePath string, gracePeriodSeconds int64) error {
	c.Valid = provider != ""
	if !c.Valid {
		return nil
	}
	var info *infoProvider
	if provider == configuration.CustomProvider {
		info = &infoProvider{js: js, key: key, response: response, validate: validate}
		c.storeCustomResourcePaths(js, challengeURL)
	} else {
		info = infoProviders[provider]
	}
	c.infoProvider = info
	c.siteKey = siteKey
	c.secretKey = secretKey
	c.gateSecret = []byte(gateSecret)
	c.gateBindIP = gateBindIP
	c.remediationCustomHeader = remediationCustomHeader
	template, contentType, _ := configuration.GetTemplate(captchaTemplatePath)
	c.template = template
	c.templateContentType = contentType
	c.gracePeriodSeconds = gracePeriodSeconds
	c.log = log
	c.httpClient = httpClient
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
		value := mintGateValue(c.gateSecret, c.gateBindIP, remoteIP, time.Now())
		setGateCookie(rw, r, value, c.gracePeriodSeconds)
		if c.remediationCustomHeader != "" {
			rw.Header().Set(c.remediationCustomHeader, "solved-captcha")
		}
		http.Redirect(rw, r, r.URL.String(), http.StatusFound)
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

// Check Verify if the captcha is already done via gate cookie.
func (c *Client) Check(r *http.Request, remoteIP string) bool {
	passed := validateGateValue(c.gateSecret, c.gateBindIP, remoteIP, gateCookieValue(r), time.Now(), c.gracePeriodSeconds)
	c.log.Debug(fmt.Sprintf("captcha:Check ip:%s pass:%v", remoteIP, passed))
	return passed
}

// IsCustomResourceRequest reports whether the request path is an exact configured widget asset.
func (c *Client) IsCustomResourceRequest(r *http.Request) bool {
	if r == nil || r.URL == nil {
		return false
	}
	requestPath := r.URL.Path
	for _, resourcePath := range c.customResourcePaths {
		if requestPath == resourcePath {
			return true
		}
	}
	return false
}

// IsCaptchaFormPost reports whether this POST carries a non-empty provider response field.
func (c *Client) IsCaptchaFormPost(r *http.Request) bool {
	if r == nil || r.Method != http.MethodPost || c.infoProvider == nil {
		return false
	}
	return captchaResponseFromRequest(r, c.infoProvider.response) != ""
}

// WriteSolvedRedirect issues 302 to the same URL without reminting the gate cookie.
func (c *Client) WriteSolvedRedirect(rw http.ResponseWriter, r *http.Request) {
	if c.remediationCustomHeader != "" {
		rw.Header().Set(c.remediationCustomHeader, "solved-captcha")
	}
	http.Redirect(rw, r, r.URL.String(), http.StatusFound)
}

// storeCustomResourcePaths keeps exact browser asset paths for custom-provider passthrough.
func (c *Client) storeCustomResourcePaths(jsURL, challengeURL string) {
	c.customResourcePaths = nil
	for _, rawURL := range []string{jsURL, challengeURL} {
		resourcePath := exactResourcePath(rawURL)
		if resourcePath == "" {
			continue
		}
		c.customResourcePaths = append(c.customResourcePaths, resourcePath)
	}
}

// exactResourcePath returns a configured URL path when it is usable as an exact match.
func exactResourcePath(rawURL string) string {
	if rawURL == "" {
		return ""
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	resourcePath := parsed.Path
	if resourcePath == "" || !strings.HasPrefix(resourcePath, "/") {
		return ""
	}
	return resourcePath
}

type responseProvider struct {
	Success bool `json:"success"`
}

// captchaResponseFromRequest reads the provider token from query, POST form, or
// raw urlencoded body. Traefik's Yaegi request wrapper often leaves Form empty
// after FormValue, so the body is parsed directly when ParseForm yields nothing.
func captchaResponseFromRequest(r *http.Request, field string) string {
	if field == "" {
		return ""
	}
	if token := r.URL.Query().Get(field); token != "" {
		return token
	}

	var raw []byte
	if r.Body != nil {
		raw, _ = io.ReadAll(io.LimitReader(r.Body, 1<<20))
		r.Body = io.NopCloser(bytes.NewReader(raw))
	}

	if err := r.ParseForm(); err == nil {
		if token := r.PostForm.Get(field); token != "" {
			return token
		}
		if token := r.Form.Get(field); token != "" {
			return token
		}
	}

	values, err := url.ParseQuery(string(raw))
	if err != nil {
		return ""
	}
	return values.Get(field)
}

// Validate Verify the captcha from provider API.
func (c *Client) Validate(r *http.Request) (bool, error) {
	if r.Method != http.MethodPost {
		c.log.Debug("captcha:Validate invalid method: " + r.Method)
		return false, nil
	}
	response := captchaResponseFromRequest(r, c.infoProvider.response)
	if response == "" {
		c.log.Debug("captcha:Validate no captcha response found in request")
		return false, nil
	}
	var body = url.Values{}
	body.Add("secret", c.secretKey)
	body.Add("response", response)
	res, err := c.httpClient.PostForm(c.infoProvider.validate, body)
	if err != nil {
		c.log.Error("captcha:Validate " + err.Error())
		return false, err
	}
	defer func() {
		_ = res.Body.Close()
	}()
	if !strings.HasPrefix(res.Header.Get("Content-Type"), "application/json") {
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

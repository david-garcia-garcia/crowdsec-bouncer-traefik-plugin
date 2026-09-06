// Package captcha implements utility for captcha management.
package captcha

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"text/template"

	cache "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
	configuration "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/configuration"
)

// trycapWidgetJS is the Cap widget script. The @ is an npm version pin, not a URL password.
//
//nolint:gosec // G101 flags npm @version in the URL
const trycapWidgetJS = "https://cdn.jsdelivr.net/npm/cap-widget@0.1.57"

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

// infoProvider is per-captchaProvider frontend JS, class-widget key, form field, verify URL, JSON siteverify flag, and Cap widget API endpoint.
type infoProvider struct {
	js          string
	key         string
	response    string
	validate    string
	jsonBody    bool
	apiEndpoint string
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

// trycapInfoProvider builds Cap Standalone widget JS, cap-token field, and JSON siteverify URLs.
func trycapInfoProvider(instanceURL, siteKey string) *infoProvider {
	base := strings.TrimRight(instanceURL, "/") + "/" + strings.Trim(siteKey, "/") + "/"
	return &infoProvider{
		js:          trycapWidgetJS,
		key:         "",
		response:    "cap-token",
		validate:    base + "siteverify",
		jsonBody:    true,
		apiEndpoint: base,
	}
}

// New Initialize captcha client.
func (c *Client) New(log *slog.Logger, cacheClient *cache.Client, httpClient *http.Client, provider, js, key, response, validate, siteKey, secretKey, trycapInstanceURL, remediationCustomHeader, captchaTemplatePath string, gracePeriodSeconds int64) error {
	c.Valid = provider != ""
	if !c.Valid {
		return nil
	}
	var info *infoProvider
	switch provider {
	case configuration.CustomProvider:
		info = &infoProvider{js: js, key: key, response: response, validate: validate}
	case configuration.TrycapProvider:
		info = trycapInfoProvider(trycapInstanceURL, siteKey)
	default:
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
		"SiteKey":        c.siteKey,
		"FrontendJS":     c.infoProvider.js,
		"FrontendKey":    c.infoProvider.key,
		"CapApiEndpoint": c.infoProvider.apiEndpoint,
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
	res, err := c.postSiteverify(r, response)
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

// postSiteverify POSTs the token: JSON for Cap Standalone, urlencoded PostForm otherwise.
func (c *Client) postSiteverify(r *http.Request, token string) (*http.Response, error) {
	if !c.infoProvider.jsonBody {
		body := url.Values{}
		body.Add("secret", c.secretKey)
		body.Add("response", token)
		return c.httpClient.PostForm(c.infoProvider.validate, body)
	}
	payload, err := json.Marshal(map[string]string{
		"secret":   c.secretKey,
		"response": token,
	})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, c.infoProvider.validate, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return c.httpClient.Do(req)
}

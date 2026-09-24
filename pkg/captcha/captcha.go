// Package captcha is the reclaim value for one named captcha Client that holds a widget and a verifier.
package captcha

import (
	"bytes"
	"io"
	"log/slog"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"text/template"
	"time"

	configuration "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

// Client is one published captcha widget, verifier, template, and gate. Not a Bouncer field.
type Client struct {
	Valid               bool
	siteKey             string
	gateSecret          []byte
	gateBindIP          bool
	gracePeriodSeconds  int64
	templateContentType string
	template            *template.Template
	httpClient          *http.Client
	log                 *slog.Logger
	widget              Widget
	verifier            Verifier
	// challengeURL is custom-only; built-ins leave it empty.
	challengeURL        string
	customResourcePaths []string
	mu                  sync.Mutex
	middlewareName      string
	instanceName        string
	incarnation         string
	sessionKey          string
	closed              bool
	sleeping            bool
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

// New fills widget, verifier, template, and gate fields. Empty provider leaves Valid false.
// New is the only provider and key-type switch. enterprise is the named recaptcha-enterprise construction value.
func (c *Client) New(log *slog.Logger, httpClient *http.Client, provider, js, challengeURL, key, response, validate, validateBody, siteKey, secretKey, gateSecret string, gateBindIP bool, captchaTemplatePath string, gracePeriodSeconds int64, enterprise Enterprise) error {
	c.Valid = provider != ""
	if !c.Valid {
		return nil
	}
	c.siteKey = siteKey
	c.gateSecret = []byte(gateSecret)
	c.gateBindIP = gateBindIP
	c.log = log
	c.httpClient = httpClient
	// Pair widget and verifier from the provider name and enterprise key type only.
	switch provider {
	case configuration.CustomProvider:
		c.challengeURL = challengeURL
		c.storeCustomResourcePaths(js, challengeURL)
		c.widget = Widget{ScriptURL: js, Class: key, TokenField: response, RetryAfterReject: true}
		c.verifier = newSiteverifyVerifier(httpClient, secretKey, validate, strings.TrimSpace(validateBody), log)
	case configuration.RecaptchaEnterpriseProvider:
		c.widget, c.verifier = pairEnterprise(httpClient, siteKey, enterprise)
	default:
		info := infoProviders[provider]
		c.widget = Widget{ScriptURL: info.js, Class: info.key, TokenField: info.response, RetryAfterReject: true}
		c.verifier = newSiteverifyVerifier(httpClient, secretKey, info.validate, "", log)
	}
	challengeTemplate, contentType, err := configuration.GetTemplate(captchaTemplatePath)
	if err != nil {
		return err
	}
	c.template = challengeTemplate
	c.templateContentType = contentType
	c.gracePeriodSeconds = gracePeriodSeconds
	return nil
}

// HTTPClientForTest returns the HTTP client the captcha Client uses for its verifier. Tests only.
func (c *Client) HTTPClientForTest() *http.Client {
	return c.httpClient
}

// ServeHTTP handles captcha html page or validation. remediationHeader is this router's name.
func (c *Client) ServeHTTP(rw http.ResponseWriter, r *http.Request, remoteIP, remediationHeader string) {
	outcome, err := c.Validate(r, remoteIP)
	// Transport and JSON decode stay classified; the solver retries the challenge.
	if err != nil {
		c.log.Info("captcha:ServeHTTP:validate", "error", err)
	}
	if outcome == Pass {
		logger.Trace(c.log, "captcha:ServeHTTP captcha:valid")
		value := mintGateValue(c.gateSecret, c.gateBindIP, remoteIP, time.Now())
		setGateCookie(rw, r, value, c.gracePeriodSeconds)
		writeRemediationHeader(rw, remediationHeader, "solved-captcha")
		http.Redirect(rw, r, r.URL.String(), http.StatusFound)
		return
	}
	bootScript := c.widget.BootScript
	if outcome == Reject && !c.widget.RetryAfterReject {
		bootScript = ""
	}
	rw.Header().Set("Content-Type", c.templateContentType)
	writeRemediationHeader(rw, remediationHeader, "captcha")
	rw.WriteHeader(http.StatusOK)
	err = c.template.Execute(rw, map[string]string{
		"SiteKey":      c.siteKey,
		"FrontendJS":   c.widget.ScriptURL,
		"FrontendKey":  c.widget.Class,
		"ChallengeURL": c.challengeURL,
		"BootScript":   bootScript,
		"Action":       c.widget.Action,
		"DrawCheckbox": c.widget.drawCheckbox(),
	})
	if err != nil {
		c.log.Info("captcha:ServeHTTP captchaTemplateServe", "error", err)
	}
}

// Check Verify if the captcha is already done via gate cookie.
func (c *Client) Check(r *http.Request, remoteIP string) bool {
	passed := validateGateValue(c.gateSecret, c.gateBindIP, remoteIP, gateCookieValue(r), time.Now(), c.gracePeriodSeconds)
	logger.Trace(c.log, "captcha:Check", "ip", remoteIP, "pass", passed)
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

// captchaFormMaxBytes is the largest POST body inspected for a provider token.
// Provider tokens are small, so a bigger body is origin traffic and is left alone.
const captchaFormMaxBytes = 64 << 10

// IsCaptchaFormPost reports whether this POST carries a non-empty provider response field.
// Its caller may still forward the request, so it never consumes the body: a POST that
// turns out not to be a captcha form reaches origin intact. Validate uses
// captchaResponseFromRequest instead, which is free to consume the body.
func (c *Client) IsCaptchaFormPost(r *http.Request) bool {
	if r == nil || r.Method != http.MethodPost || c.widget.TokenField == "" {
		return false
	}
	field := c.widget.TokenField
	// Something upstream already parsed the form; rereading Body would find nothing.
	if r.PostForm != nil {
		return r.PostForm.Get(field) != ""
	}
	// A declared body over the cap is origin traffic; do not buffer it to hunt for a token.
	if r.ContentLength > captchaFormMaxBytes {
		return false
	}
	body, withinCap := peekCaptchaFormBody(r)
	if !withinCap {
		return false
	}
	return formFieldValue(r.Header.Get("Content-Type"), body, field) != ""
}

// peekCaptchaFormBody reads up to captchaFormMaxBytes and always leaves r.Body readable.
// It reports the buffered body, and false when the body exceeds the cap or could not be
// read — which also covers a request whose Content-Length is unknown and whose body turns
// out to be large.
func peekCaptchaFormBody(r *http.Request) ([]byte, bool) {
	if r.Body == nil {
		return nil, false
	}
	peeked, err := io.ReadAll(io.LimitReader(r.Body, captchaFormMaxBytes+1))
	if err != nil || len(peeked) > captchaFormMaxBytes {
		r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(peeked), r.Body))
		return nil, false
	}
	_ = r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(peeked))
	r.ContentLength = int64(len(peeked))
	return peeked, true
}

// formFieldValue returns one field of an already-buffered urlencoded or multipart body.
// A body with no usable Content-Type is read as urlencoded, which is what the bundled
// captcha form sends.
func formFieldValue(contentType string, body []byte, field string) string {
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		mediaType = "application/x-www-form-urlencoded"
	}
	switch mediaType {
	case "application/x-www-form-urlencoded":
		values, parseErr := url.ParseQuery(string(body))
		if parseErr != nil {
			return ""
		}
		return values.Get(field)
	case "multipart/form-data":
		return multipartFieldValue(params["boundary"], body, field)
	default:
		return ""
	}
}

// multipartFieldValue reads one form value out of a buffered multipart body.
func multipartFieldValue(boundary string, body []byte, field string) string {
	if boundary == "" {
		return ""
	}
	// The body is already capped, so this parse never spills to a temporary file.
	form, err := multipart.NewReader(bytes.NewReader(body), boundary).ReadForm(captchaFormMaxBytes)
	if err != nil {
		return ""
	}
	defer func() { _ = form.RemoveAll() }()
	values := form.Value[field]
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

// WriteSolvedRedirect issues 302 to the same URL without reminting the gate cookie.
func (c *Client) WriteSolvedRedirect(rw http.ResponseWriter, r *http.Request, remediationHeader string) {
	writeRemediationHeader(rw, remediationHeader, "solved-captcha")
	http.Redirect(rw, r, r.URL.String(), http.StatusFound)
}

// writeRemediationHeader sets this router's captcha-kind header when a name is configured.
func writeRemediationHeader(rw http.ResponseWriter, name, value string) {
	if name == "" {
		return
	}
	rw.Header().Set(name, value)
}

// Close releases idle siteverify HTTP. Safe to call more than once.
func (c *Client) Close() {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	c.sleeping = false
	httpClient := c.httpClient
	c.mu.Unlock()
	if httpClient != nil {
		httpClient.CloseIdleConnections()
	}
	c.log.Info(MsgInstanceClosed, "incarnation", c.incarnation, "reason", "closed")
}

// Sleep logs DEBUG. Captcha has no ticker.
func (c *Client) Sleep() {
	c.mu.Lock()
	if c.closed || c.sleeping {
		c.mu.Unlock()
		return
	}
	c.sleeping = true
	c.mu.Unlock()
	c.log.Debug(MsgInstanceSleeping, "incarnation", c.incarnation, "reason", "sleeping")
}

// Wake logs DEBUG after Sleep. Captcha has no ticker.
func (c *Client) Wake() {
	c.mu.Lock()
	if c.closed || !c.sleeping {
		c.mu.Unlock()
		return
	}
	c.sleeping = false
	c.mu.Unlock()
	c.log.Debug(MsgInstanceWaking, "incarnation", c.incarnation, "reason", "waking")
}

// Incarnation is unique per Client create.
func (c *Client) Incarnation() string {
	if c == nil {
		return ""
	}
	return c.incarnation
}

func (c *Client) bindIdentity(middlewareName, bindKey string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.middlewareName == "" {
		c.middlewareName = middlewareName
	}
	if c.sessionKey == "" {
		c.sessionKey = bindKey
	}
}

// storeCustomResourcePaths keeps exact browser asset paths for custom-provider passthrough.
func (c *Client) storeCustomResourcePaths(jsURL, challengeURL string) {
	c.customResourcePaths = nil
	for _, rawURL := range []string{jsURL, challengeURL} {
		resourcePath := configuration.CustomCaptchaResourcePath(rawURL)
		if resourcePath == "" {
			continue
		}
		c.customResourcePaths = append(c.customResourcePaths, resourcePath)
	}
}

// captchaResponseFromRequest reads the provider token from query, POST form, or
// raw urlencoded body. Traefik's Yaegi request wrapper often leaves Form empty
// after FormValue, so the body is parsed directly when ParseForm yields nothing.
//
// This is the first-verify reader, used only by Validate on a request the plugin
// answers itself. It parses the form and truncates a body over 1MiB, which is safe
// only because that request is never forwarded. Routing decisions on a request that
// may still reach origin use IsCaptchaFormPost.
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

// Validate classifies the challenge request as None, Pass, or Reject.
// Empty token is None and does not call the verifier. Error is the error return.
func (c *Client) Validate(r *http.Request, remoteIP string) (Outcome, error) {
	if r.Method != http.MethodPost {
		logger.Trace(c.log, "captcha:Validate invalid method", "method", r.Method)
		return None, nil
	}
	token := captchaResponseFromRequest(r, c.widget.TokenField)
	if token == "" {
		logger.Trace(c.log, "captcha:Validate no captcha response found in request")
		return None, nil
	}
	passed, err := c.verifier.Pass(token, remoteIP)
	if err != nil {
		c.log.Debug("captcha:Validate", "error", err)
		return None, err
	}
	if passed {
		return Pass, nil
	}
	return Reject, nil
}

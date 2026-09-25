// Package captcha is the reclaim value for one named captcha Client that holds a widget and a verifier.
package captcha

import (
	"html"
	"log/slog"
	"net"
	"net/http"
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

const msgCaptchaTemplateUnavailable = "crowdsec captcha template unavailable"

// New fills widget, verifier, template, and gate fields. Empty provider leaves Valid false.
// New is the only provider switch. Each named provider calls its pair function.
// enterprise is the recaptcha-enterprise construction value. Custom also stores the
// challenge URL and the asset paths the bouncer lets through.
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
	// Pair functions return Verifier. Yaegi v0.16.1 panics if this multi-value
	// assignment receives the concrete verifier instead.
	var widget Widget
	var verifier Verifier
	switch provider {
	case configuration.CustomProvider:
		widget, verifier = pairCustom(httpClient, secretKey, js, key, response, validate, validateBody, log)
		// Challenge URL and asset paths are custom-only. The other providers have none.
		c.challengeURL = challengeURL
		c.storeCustomResourcePaths(js, challengeURL)
	case configuration.RecaptchaEnterpriseProvider:
		widget, verifier = pairEnterprise(httpClient, siteKey, enterprise)
	case configuration.EucaptchaProvider:
		widget, verifier = pairEucaptcha(httpClient, siteKey, secretKey)
	case configuration.HcaptchaProvider, configuration.RecaptchaProvider, configuration.TurnstileProvider:
		widget, verifier = pairSiteverify(httpClient, provider, secretKey, log)
	}
	c.widget = widget
	c.verifier = verifier
	challengeTemplate, contentType, err := configuration.GetTemplate(captchaTemplatePath)
	if err != nil {
		c.Valid = false
		c.gracePeriodSeconds = gracePeriodSeconds
		c.log = log
		c.httpClient = httpClient
		c.log.Warn(msgCaptchaTemplateUnavailable, "reason", configuration.TemplateUnavailableReason(captchaTemplatePath, err))
		return nil
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
		rw.Header().Set("Cache-Control", "no-cache, no-store")
		http.Redirect(rw, r, r.URL.String(), http.StatusFound)
		return
	}
	bootScript := c.widget.BootScript
	if outcome == Reject && !c.widget.RetryAfterReject {
		bootScript = ""
	}
	rw.Header().Set("Content-Type", c.templateContentType)
	rw.Header().Set("Cache-Control", "no-cache, no-store")
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
		"Domain":       html.EscapeString(RequestDomain(r.Host)),
	})
	if err != nil {
		c.log.Info("captcha:ServeHTTP captchaTemplateServe", "error", err)
	}
}

// RequestDomain is the hostname the browser showed, without a port.
func RequestDomain(host string) string {
	name := host
	if parsed, _, err := net.SplitHostPort(host); err == nil {
		name = parsed
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return "This site"
	}
	return name
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

// IsCaptchaFormPost reports whether this POST carries a non-empty provider response field.
// Its caller may still forward the request, so it never consumes the body: a POST that
// turns out not to be a captcha form reaches origin intact. Validate uses
// readFieldFromRequest instead, which is free to consume the body.
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

// WriteSolvedRedirect issues 302 to the same URL without reminting the gate cookie.
func (c *Client) WriteSolvedRedirect(rw http.ResponseWriter, r *http.Request, remediationHeader string) {
	writeRemediationHeader(rw, remediationHeader, "solved-captcha")
	rw.Header().Set("Cache-Control", "no-cache, no-store")
	http.Redirect(rw, r, r.URL.String(), http.StatusFound)
}

// writeRemediationHeader sets this router's captcha-kind header when a name is configured.
func writeRemediationHeader(rw http.ResponseWriter, name, value string) {
	if name == "" {
		return
	}
	rw.Header().Set(name, value)
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
	c.log.Info("crowdsec captcha instance closed", "incarnation", c.incarnation, "reason", "closed")
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
	c.log.Debug("crowdsec captcha instance sleeping", "incarnation", c.incarnation, "reason", "sleeping")
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
	c.log.Debug("crowdsec captcha instance waking", "incarnation", c.incarnation, "reason", "waking")
}

// Incarnation is unique per Client create.
func (c *Client) Incarnation() string {
	if c == nil {
		return ""
	}
	return c.incarnation
}

// bindIdentity records the middleware name and reclaim key the first time Open binds this Client.
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

// Validate classifies the challenge request as None, Pass, or Reject.
// Empty token is None and does not call the verifier. Error is the error return.
func (c *Client) Validate(r *http.Request, remoteIP string) (Outcome, error) {
	if r.Method != http.MethodPost {
		logger.Trace(c.log, "captcha:Validate invalid method", "method", r.Method)
		return None, nil
	}
	token := readFieldFromRequest(r, c.widget.TokenField)
	if token == "" {
		logger.Trace(c.log, "captcha:Validate no captcha response found in request")
		return None, nil
	}
	passed, err := c.verifier.Pass(token, remoteIP, r.UserAgent())
	if err != nil {
		c.log.Debug("captcha:Validate", "error", err)
		return None, err
	}
	if passed {
		return Pass, nil
	}
	return Reject, nil
}

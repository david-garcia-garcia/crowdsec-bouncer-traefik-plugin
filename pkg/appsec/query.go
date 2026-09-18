package appsec

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	configuration "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/configuration"
)

const (
	crowdsecAppsecIPHeader   = "X-Crowdsec-Appsec-Ip"
	crowdsecAppsecURIHeader  = "X-Crowdsec-Appsec-Uri"
	crowdsecAppsecHostHeader = "X-Crowdsec-Appsec-Host"
	crowdsecAppsecVerbHeader = "X-Crowdsec-Appsec-Verb"
	crowdsecAppsecHeader     = "X-Crowdsec-Appsec-Api-Key"
	crowdsecAppsecUserAgent  = "X-Crowdsec-Appsec-User-Agent"
	appsecResponseBodyLimit  = 1 << 20 // 1 MiB
)

// Structured AppSec JSON action values CrowdSec 1.8 puts in the envelope body.
const (
	ActionAllow     = "allow"
	ActionBan       = "ban"
	ActionCaptcha   = "captcha"
	ActionChallenge = "challenge"
)

// Policy is per-route AppSec fallback when the listener does not return a usable verdict.
type Policy struct {
	FailureAction string
}

// ErrFailureCaptcha tells the bouncer to run pkg/captcha instead of ban or next.
var ErrFailureCaptcha = errors.New("failureAction captcha")

// errAppsecReadBody is the io failure from readCappedAppsecBody (not an oversized body).
var errAppsecReadBody = errors.New("appsecQuery:readBody")

// resultForFailureAction maps a configured fallback to allow, captcha, or an error ban.
func resultForFailureAction(action, errMsg string) (*Response, error) {
	switch configuration.EffectiveFailureAction(action) {
	case configuration.FailureActionPassthrough:
		return appsecAllow(), nil
	case configuration.FailureActionCaptcha:
		return nil, ErrFailureCaptcha
	default:
		return nil, errors.New(errMsg)
	}
}

// resultForFailureActionErr is resultForFailureAction when only an error is needed (request build).
func resultForFailureActionErr(action, errMsg string) error {
	_, err := resultForFailureAction(action, errMsg)
	return err
}

// Response is the structured AppSec JSON envelope CrowdSec 1.8 returns for a remediation.
// Field tags match CrowdSec's snake_case wire names (http_status, user_body_content, …).
//
//nolint:tagliatelle
type Response struct {
	Action          string              `json:"action"`
	HTTPStatus      int                 `json:"http_status"`
	UserBodyContent string              `json:"user_body_content,omitempty"`
	UserCookies     []string            `json:"user_cookies,omitempty"`
	UserHeaders     map[string][]string `json:"user_headers,omitempty"`
}

// appsecAllow returns a pass-through decision so Query never uses (nil, nil).
func appsecAllow() *Response {
	return &Response{Action: ActionAllow}
}

func isBodyUnreadable(httpReq *http.Request) bool {
	return httpReq.Body != nil && httpReq.Body != http.NoBody && httpReq.ProtoMajor >= 2 && httpReq.ContentLength < 0
}

// isMethodWithBody reports whether an unreadable body on this method is a drop candidate.
func isMethodWithBody(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch:
		return true
	default:
		return false
	}
}

// isMethodWithForwardableBody reports whether a readable body on this method is copied to AppSec.
// Deliberately wider than isMethodWithBody: a DELETE body is worth inspecting, but an unreadable
// DELETE body is not a drop candidate. Keep the two sets separate.
func isMethodWithForwardableBody(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

// isHopByHopHeader reports whether a header is connection-scoped (RFC 7230 section 6.1, errata 4522)
// and therefore must not be forwarded to the AppSec listener.
func isHopByHopHeader(name string) bool {
	switch strings.ToLower(name) {
	case "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
		"te", "trailer", "transfer-encoding", "upgrade":
		return true
	default:
		return false
	}
}

// Query forwards the request to this AppSec HTTP client.
// A structured JSON envelope is returned when AppSec supplies a non-empty action.
func (c *Client) Query(ip string, httpReq *http.Request, pol Policy) (*Response, error) {
	req, err := c.newAppsecForwardRequest(ip, httpReq, pol)
	if err != nil {
		return nil, err
	}

	current := c.currentTransport()
	if current == nil || current.httpClient == nil {
		c.log.Error("appsecQuery:unreachable")
		return resultForFailureAction(pol.FailureAction, "appsecQuery:unreachable")
	}
	if skipErr := c.admitQuery(httpReq.Context()); skipErr != nil {
		return resultForFailureAction(pol.FailureAction, skipErr.Error())
	}
	res, err := current.httpClient.Do(req)
	if err != nil {
		c.reportQuery(false)
		c.log.Error("appsecQuery:unreachable")
		return resultForFailureAction(pol.FailureAction, "appsecQuery:unreachable")
	}
	// Drain every live response, including 502/503/504, so keep-alive can reuse the slot.
	defer c.drainResponse(res)
	if isReverseProxyError(res.StatusCode) {
		c.reportQuery(false)
		c.log.Error("appsecQuery:unreachable")
		return resultForFailureAction(pol.FailureAction, "appsecQuery:unreachable")
	}

	if res.StatusCode == http.StatusInternalServerError {
		c.reportQuery(false)
		c.log.Info("appsecQuery:failure")
		return resultForFailureAction(pol.FailureAction, "appsecQuery statusCode:500")
	}

	body, err := c.readCappedAppsecBody(res)
	if err != nil {
		// After an admitted Do the backend answered; io/oversized still Report success.
		c.reportQuery(true)
		// Io errors use FailureAction; oversized bodies stay as dest (allow 200 / error otherwise).
		if errors.Is(err, errAppsecReadBody) {
			c.log.Info("appsecQuery:failure")
			return resultForFailureAction(pol.FailureAction, err.Error())
		}
		return nil, err
	}
	c.reportQuery(true)
	return interpretAppsecBody(res.StatusCode, body, c.log)
}

// admitQuery Allow-checks the AppSec stem. A nil Gate admits. Denied or Allow-error skips Do.
func (c *Client) admitQuery(ctx context.Context) error {
	if c.gate == nil {
		return nil
	}
	ok, wait, err := c.gate.Allow(ctx, c.backendURLStem())
	if err != nil || !ok {
		c.log.Debug("appsecQuery:skipped", "wait", wait)
		return errors.New("appsecQuery:skipped")
	}
	return nil
}

// reportQuery records the admitted Do outcome. A nil Gate is a no-op.
func (c *Client) reportQuery(success bool) {
	if c.gate == nil {
		return
	}
	_ = c.gate.Report(c.backendURLStem(), success)
}

// newAppsecForwardRequest builds the AppSec listener request, copying client headers and identity.
func (c *Client) newAppsecForwardRequest(ip string, httpReq *http.Request, pol Policy) (*http.Request, error) {
	routeURL := url.URL{
		Scheme: c.appsecScheme,
		Host:   c.appsecHost,
		Path:   c.appsecPath,
	}
	req, err := c.newAppsecBodyRequest(routeURL.String(), httpReq, pol)
	if err != nil {
		return nil, err
	}
	// Omit hop-by-hop headers (Transfer-Encoding among them) and the client Content-Length;
	// the length is rebuilt below from the bytes actually forwarded.
	for key, headers := range httpReq.Header {
		if isHopByHopHeader(key) || strings.EqualFold(key, "Content-Length") {
			continue
		}
		for _, value := range headers {
			req.Header.Add(key, value)
		}
	}
	// POST is the only outbound method that carries bytes; a bodyless GET gets no length header.
	if req.Method == http.MethodPost {
		req.Header.Set("Content-Length", strconv.FormatInt(req.ContentLength, 10))
	}
	current := c.currentTransport()
	appsecKey := ""
	if current != nil {
		appsecKey = current.key
	}
	req.Header.Set(crowdsecAppsecHeader, appsecKey)
	req.Header.Set(crowdsecAppsecIPHeader, ip)
	req.Header.Set(crowdsecAppsecVerbHeader, httpReq.Method)
	req.Header.Set(crowdsecAppsecHostHeader, httpReq.Host)
	req.Header.Set(crowdsecAppsecURIHeader, httpReq.URL.String())
	req.Header.Set(crowdsecAppsecUserAgent, httpReq.Header.Get("User-Agent"))
	req.Header.Set("User-Agent", "Crowdsec-Bouncer-Traefik-Plugin/"+c.pluginVersion)
	return req, nil
}

// newAppsecBodyRequest chooses GET (no, unreadable, or non-body-method body) or POST (copied client
// body) toward AppSec. The original verb always travels on X-Crowdsec-Appsec-Verb.
func (c *Client) newAppsecBodyRequest(target string, httpReq *http.Request, pol Policy) (*http.Request, error) {
	switch {
	case isBodyUnreadable(httpReq):
		if isMethodWithBody(httpReq.Method) && configuration.EffectiveFailureAction(pol.FailureAction) != configuration.FailureActionPassthrough {
			return nil, resultForFailureActionErr(pol.FailureAction, "appsecQuery:unreadableBody dropped")
		}
		req, _ := http.NewRequest(http.MethodGet, target, nil)
		return req, nil
	case httpReq.Body != nil && httpReq.Body != http.NoBody && isMethodWithForwardableBody(httpReq.Method):
		// Readable body: cap with LimitReader only when the operator set a positive limit.
		var bodyBuffer bytes.Buffer
		bodyReader := io.Reader(httpReq.Body)
		if c.appsecBodyLimit > 0 {
			bodyReader = io.LimitReader(httpReq.Body, c.appsecBodyLimit)
		}
		teeReader := io.TeeReader(bodyReader, &bodyBuffer)
		bodyBytes, err := io.ReadAll(teeReader)
		if err != nil {
			return nil, fmt.Errorf("appsecQuery:GetBody %w", err)
		}
		httpReq.Body = io.NopCloser(io.MultiReader(&bodyBuffer, httpReq.Body))
		req, _ := http.NewRequest(http.MethodPost, target, bytes.NewBuffer(bodyBytes))
		req.ContentLength = int64(len(bodyBytes))
		return req, nil
	default:
		req, _ := http.NewRequest(http.MethodGet, target, nil)
		return req, nil
	}
}

// drainResponse consumes leftover bytes so the AppSec HTTP connection can be reused.
func (c *Client) drainResponse(res *http.Response) {
	if _, errDrain := io.Copy(io.Discard, res.Body); errDrain != nil {
		c.log.Debug("appsecQuery:drainBody " + errDrain.Error())
	}
	if errClose := res.Body.Close(); errClose != nil {
		c.log.Error("appsecQuery:closeBody " + errClose.Error())
	}
}

// readCappedAppsecBody reads at most 1 MiB. Oversized HTTP 200 is treated as allow; oversized non-200 is an error.
func (c *Client) readCappedAppsecBody(res *http.Response) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(res.Body, appsecResponseBodyLimit+1))
	if err != nil {
		return nil, fmt.Errorf("%w %s", errAppsecReadBody, err.Error())
	}
	if len(body) <= appsecResponseBodyLimit {
		return body, nil
	}
	c.log.Debug("appsecQuery:responseBodyTooLarge")
	if res.StatusCode == http.StatusOK {
		return []byte{}, nil
	}
	return nil, fmt.Errorf("appsecQuery:responseBodyTooLarge statusCode:%d", res.StatusCode)
}

// interpretAppsecBody maps a listener status and JSON body to an allow, structured envelope, or error.
func interpretAppsecBody(statusCode int, body []byte, log *slog.Logger) (*Response, error) {
	decision, parseErr := parseResponse(body)
	if parseErr == nil && decision.Action != "" {
		return decision, nil
	}
	if parseErr != nil && len(bytes.TrimSpace(body)) > 0 {
		log.Debug("appsecQuery:parseBody " + parseErr.Error())
	}
	if statusCode == http.StatusOK {
		return appsecAllow(), nil
	}
	return nil, fmt.Errorf("appsecQuery statusCode:%d", statusCode)
}

// parseResponse unmarshals a CrowdSec AppSec JSON envelope. Empty bodies are not structured.
func parseResponse(body []byte) (*Response, error) {
	body = bytes.TrimSpace(body)
	if len(body) == 0 {
		return nil, errors.New("empty appsec response body")
	}
	var decision Response
	if err := json.Unmarshal(body, &decision); err != nil {
		return nil, err
	}
	return &decision, nil
}

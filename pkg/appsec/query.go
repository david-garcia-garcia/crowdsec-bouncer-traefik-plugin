package appsec

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"

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

// Policy is per-route AppSec fallback and unreadable-body drop.
type Policy struct {
	FailureAction       string
	UnreadableBodyBlock bool
}

// ErrFailureCaptcha tells the bouncer to run pkg/captcha instead of ban or next.
var ErrFailureCaptcha = errors.New("failureAction captcha")

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

// isBodyUnreadable is true for HTTP/2+ requests with a body and no Content-Length (gRPC streams).
func isBodyUnreadable(httpReq *http.Request) bool {
	return httpReq.Body != nil && httpReq.Body != http.NoBody && httpReq.ProtoMajor >= 2 && httpReq.ContentLength < 0
}

// isMethodWithBody is true for methods that may carry a request body toward AppSec.
func isMethodWithBody(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
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

	res, err := c.httpClient.Do(req)
	if err != nil || isReverseProxyError(res.StatusCode) {
		c.log.Error("appsecQuery:unreachable")
		return resultForFailureAction(pol.FailureAction, "appsecQuery:unreachable")
	}
	defer c.drainResponse(res)

	if res.StatusCode == http.StatusInternalServerError {
		c.log.Info("appsecQuery:failure")
		return resultForFailureAction(pol.FailureAction, "appsecQuery statusCode:500")
	}

	body, err := c.readCappedAppsecBody(res)
	if err != nil {
		return nil, err
	}
	return interpretAppsecBody(res.StatusCode, body, c.log)
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
	for key, headers := range httpReq.Header {
		for _, value := range headers {
			req.Header.Add(key, value)
		}
	}
	req.Header.Set(crowdsecAppsecHeader, c.appsecKey)
	req.Header.Set(crowdsecAppsecIPHeader, ip)
	req.Header.Set(crowdsecAppsecVerbHeader, httpReq.Method)
	req.Header.Set(crowdsecAppsecHostHeader, httpReq.Host)
	req.Header.Set(crowdsecAppsecURIHeader, httpReq.URL.String())
	req.Header.Set(crowdsecAppsecUserAgent, httpReq.Header.Get("User-Agent"))
	req.Header.Set("User-Agent", "Crowdsec-Bouncer-Traefik-Plugin/"+c.pluginVersion)
	return req, nil
}

// newAppsecBodyRequest chooses GET (no/unreadable body) or POST (copied client body) toward AppSec.
func (c *Client) newAppsecBodyRequest(target string, httpReq *http.Request, pol Policy) (*http.Request, error) {
	switch {
	case isBodyUnreadable(httpReq):
		if pol.UnreadableBodyBlock && isMethodWithBody(httpReq.Method) {
			return nil, errors.New("appsecQuery:unreadableBody dropped")
		}
		// HTTP/2+ streams have no finite body to copy; inspect headers only (issue #323).
		req, _ := http.NewRequest(http.MethodGet, target, nil)
		return req, nil
	case c.appsecBodyLimit > 0 && httpReq.Body != nil:
		var bodyBuffer bytes.Buffer
		limitedReader := io.LimitReader(httpReq.Body, c.appsecBodyLimit)
		teeReader := io.TeeReader(limitedReader, &bodyBuffer)
		bodyBytes, err := io.ReadAll(teeReader)
		if err != nil {
			return nil, fmt.Errorf("appsecQuery:GetBody %w", err)
		}
		httpReq.Body = io.NopCloser(io.MultiReader(&bodyBuffer, httpReq.Body))
		req, _ := http.NewRequest(http.MethodPost, target, bytes.NewBuffer(bodyBytes))
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
		return nil, fmt.Errorf("appsecQuery:readBody %w", err)
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

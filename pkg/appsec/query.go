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
	"time"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/clientrequest"
	configuration "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

const (
	crowdsecAppsecIPHeader          = "X-Crowdsec-Appsec-Ip"
	crowdsecAppsecURIHeader         = "X-Crowdsec-Appsec-Uri"
	crowdsecAppsecHostHeader        = "X-Crowdsec-Appsec-Host"
	crowdsecAppsecVerbHeader        = "X-Crowdsec-Appsec-Verb"
	crowdsecAppsecHeader            = "X-Crowdsec-Appsec-Api-Key"
	crowdsecAppsecUserAgent         = "X-Crowdsec-Appsec-User-Agent"
	crowdsecAppsecHTTPVersionHeader = "X-Crowdsec-Appsec-Http-Version"
	appsecResponseBodyLimit         = 1 << 20 // 1 MiB
)

// msgUnauthenticated is the debounced WARN for HTTP 401. The text is the AppSec protocol sentence.
const msgUnauthenticated = "Remediation component is not authenticated."

// msgUnexpectedListenerStatus is the debounced WARN when the listener status is not 200, 401, 403, or 500.
const msgUnexpectedListenerStatus = "The remediation component returned an unexpected status code"

// msgBodyReadTimeout is the debounced WARN when a client body of unknown length misses appsecBodyReadTimeoutSeconds.
const msgBodyReadTimeout = "AppSec request body not received within appsecBodyReadTimeoutSeconds; request blocked. " +
	"Exclude streaming routes with a bouncerActionRules bypassAppsec rule"

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

// ErrClientDisconnected is a classified client disconnect while buffering a readable body.
// Query MUST NOT call AppSec or apply FailureAction; the bouncer stops without a ban.
var ErrClientDisconnected = errors.New("appsecQuery:clientDisconnected")

// ErrBodyReadTimeout is a client body of unknown length that did not end (or reach appsecBodyLimit)
// within appsecBodyReadTimeoutSeconds. Query MUST NOT call AppSec or apply FailureAction;
// the bouncer serves it as its own ban. It takes precedence over ErrClientDisconnected.
var ErrBodyReadTimeout = errors.New("appsecQuery:bodyReadTimeout")

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

// isBodyLengthUnknown reports a client body with no declared length (HTTP/1.1 chunked, HTTP/2 or
// HTTP/3 without Content-Length). Only such a body is read under appsecBodyReadTimeoutSeconds.
func isBodyLengthUnknown(httpReq *http.Request) bool {
	return httpReq.ContentLength < 0
}

// isClientGoneBodyReadErr reports disconnect or cancel while buffering a readable client body.
func isClientGoneBodyReadErr(err error) bool {
	return errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, io.ErrUnexpectedEOF)
}

// isMethodWithForwardableBody reports whether a client body on this method is copied to AppSec.
// Every other method goes headers-only, so a GET carrying a body is never read or laundered into a POST.
func isMethodWithForwardableBody(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

// hasBodyForAppsec reports a client body that is copied to AppSec: present, not http.NoBody, and on
// a method in isMethodWithForwardableBody. Any other request goes to AppSec headers-only.
func hasBodyForAppsec(httpReq *http.Request) bool {
	if httpReq.Body == nil || httpReq.Body == http.NoBody {
		return false
	}
	return isMethodWithForwardableBody(httpReq.Method)
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
// The status table in the body is the CrowdSec AppSec protocol this method follows.
// responseController belongs to the inbound response writer; the body-read deadline uses it to cut
// a stalled read. nil is allowed and falls back to closing the request body.
func (c *Client) Query(req clientrequest.Request, pol Policy, responseController *http.ResponseController) (*Response, error) {
	appsecReq, err := c.newAppsecForwardRequest(req, responseController)
	if err != nil {
		return nil, err
	}

	current := c.currentTransport()
	if current == nil || current.httpClient == nil {
		c.log.Error("appsecQuery:unreachable")
		return resultForFailureAction(pol.FailureAction, "appsecQuery:unreachable")
	}
	res, err := current.httpClient.Do(appsecReq)
	if err != nil {
		c.log.Error("appsecQuery:unreachable")
		return resultForFailureAction(pol.FailureAction, "appsecQuery:unreachable")
	}
	// Drain every live response, including unexpected statuses, so keep-alive can reuse the slot.
	defer c.drainResponse(res)
	// CrowdSec AppSec response (https://docs.crowdsec.net/docs/appsec/protocol):
	//
	//	Code  Description                                      Body
	//	200   The HTTP request is allowed                      {"action":"allow"}
	//	403   One or more AppSec rules matched                 {"action":"ban","http_status":403},
	//	                                                       {"action":"captcha","http_status":403},
	//	                                                       or {"action":"challenge",...}
	//	500   Error in the AppSec component. Apply             null
	//	      APPSEC_FAILURE_ACTION (bouncerAppsecFailureAction).
	//	401   Remediation component is not authenticated.      null
	//	      Use the same API key that pulls the local API.
	//
	// A 200 with no parseable action is still allow. A 403 with no parseable action is still a ban
	// and does not use FailureAction. 500 uses FailureAction. 401 uses FailureAction and logs the
	// protocol sentence. Any other code uses FailureAction and logs a WARN debounced on that message text.
	if res.StatusCode == http.StatusInternalServerError {
		logger.Debounced(c.log, slog.LevelInfo, 5*time.Second, "appsecQuery:failure")
		return resultForFailureAction(pol.FailureAction, "appsecQuery statusCode:500")
	}
	if res.StatusCode == http.StatusUnauthorized {
		logger.Debounced(c.log, slog.LevelWarn, 5*time.Second, msgUnauthenticated)
		return resultForFailureAction(pol.FailureAction, "appsecQuery statusCode:401")
	}
	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusForbidden {
		logger.Debounced(c.log, slog.LevelWarn, 5*time.Second, msgUnexpectedListenerStatus, "statusCode", res.StatusCode)
		return resultForFailureAction(pol.FailureAction, fmt.Sprintf("appsecQuery statusCode:%d", res.StatusCode))
	}

	body, err := c.readCappedAppsecBody(res)
	if err != nil {
		// Io errors use FailureAction; oversized bodies stay as dest (allow 200 / error otherwise).
		if errors.Is(err, errAppsecReadBody) {
			c.log.Info("appsecQuery:failure")
			return resultForFailureAction(pol.FailureAction, err.Error())
		}
		return nil, err
	}
	// Only 200 and 403 reach here. interpretAppsecBody turns a missing action into allow or a ban.
	decision, err := interpretAppsecBody(res.StatusCode, body, c.log)
	if err != nil {
		return nil, err
	}
	return decision, nil
}

// newAppsecForwardRequest builds the AppSec listener request, copying client headers and identity.
func (c *Client) newAppsecForwardRequest(req clientrequest.Request, responseController *http.ResponseController) (*http.Request, error) {
	routeURL := url.URL{
		Scheme: c.appsecScheme,
		Host:   c.appsecHost,
		Path:   c.appsecPath,
	}
	appsecReq, err := c.newAppsecBodyRequest(routeURL.String(), req, responseController)
	if err != nil {
		return nil, err
	}
	// Omit hop-by-hop headers (Transfer-Encoding among them) and the client Content-Length;
	// the length is rebuilt below from the bytes actually forwarded.
	for key, headers := range req.Header {
		if isHopByHopHeader(key) || strings.EqualFold(key, "Content-Length") {
			continue
		}
		for _, value := range headers {
			appsecReq.Header.Add(key, value)
		}
	}
	// POST is the only outbound method that carries bytes; a bodyless GET gets no length header.
	if appsecReq.Method == http.MethodPost {
		appsecReq.Header.Set("Content-Length", strconv.FormatInt(appsecReq.ContentLength, 10))
	}
	current := c.currentTransport()
	appsecKey := ""
	if current != nil {
		appsecKey = current.key
	}
	appsecReq.Header.Set(crowdsecAppsecHeader, appsecKey)
	appsecReq.Header.Set(crowdsecAppsecIPHeader, req.IPAddrString())
	appsecReq.Header.Set(crowdsecAppsecVerbHeader, req.Method)
	appsecReq.Header.Set(crowdsecAppsecHostHeader, req.Host)
	appsecReq.Header.Set(crowdsecAppsecURIHeader, req.AbsoluteURL())
	appsecReq.Header.Set(crowdsecAppsecUserAgent, req.Header.Get("User-Agent"))
	appsecReq.Header.Set("User-Agent", "Crowdsec-Bouncer-Traefik-Plugin/"+c.pluginVersion)
	// Two ASCII digits, major then minor, so AppSec can populate r.Proto. Skip 0 so AppSec keeps the listener proto.
	if req.ProtoMajor > 0 {
		appsecReq.Header.Set(crowdsecAppsecHTTPVersionHeader, fmt.Sprintf("%d%d", req.ProtoMajor, req.ProtoMinor))
	}
	return appsecReq, nil
}

// newAppsecBodyRequest chooses GET (no body, or a method whose body is not inspected) or POST (copied
// client body) toward AppSec. The original verb always travels on X-Crowdsec-Appsec-Verb.
func (c *Client) newAppsecBodyRequest(target string, req clientrequest.Request, responseController *http.ResponseController) (*http.Request, error) {
	if !hasBodyForAppsec(req.Request) {
		appsecReq, _ := http.NewRequest(http.MethodGet, target, nil)
		return appsecReq, nil
	}
	bodyBytes, err := c.copyClientBodyForAppsecAndRestoreForOrigin(req, responseController)
	if err != nil {
		return nil, err
	}
	appsecReq, _ := http.NewRequest(http.MethodPost, target, bytes.NewBuffer(bodyBytes))
	appsecReq.ContentLength = int64(len(bodyBytes))
	return appsecReq, nil
}

// copyClientBodyForAppsecAndRestoreForOrigin copies up to appsecBodyLimit bytes of the client body for
// AppSec and restores the full body for origin on req. A body of unknown length must arrive within
// appsecBodyReadTimeoutSeconds, else ErrBodyReadTimeout. A client gone mid-read is ErrClientDisconnected.
func (c *Client) copyClientBodyForAppsecAndRestoreForOrigin(req clientrequest.Request, responseController *http.ResponseController) ([]byte, error) {
	clientBody := req.Body
	deadlineTimer := c.armBodyReadDeadline(req, responseController)

	// Copy at most appsecBodyLimit bytes; the tee keeps them for the origin restore below.
	var bodyBuffer bytes.Buffer
	bodyBytes, err := io.ReadAll(io.TeeReader(io.LimitReader(clientBody, c.appsecBodyLimit), &bodyBuffer))

	// The plugin's own timer is the only classifier of a deadline, checked before the read error:
	// a cut read can look like a client disconnect, or even succeed when the timer races the last byte.
	if bodyReadDeadlineFired(deadlineTimer) {
		logger.Debounced(c.log, slog.LevelWarn, 5*time.Second, msgBodyReadTimeout,
			"ip", req.IPAddrString(),
			"method", req.Method,
			"host", req.Host,
			"path", req.URL.Path,
			"timeoutSeconds", c.bodyReadTimeoutSeconds)
		return nil, ErrBodyReadTimeout
	}

	// Classify the remaining read failures: client gone, or an unclassified GetBody fault.
	if err != nil {
		if isClientGoneBodyReadErr(err) {
			return nil, ErrClientDisconnected
		}
		return nil, fmt.Errorf("appsecQuery:GetBody %w", err)
	}

	// Give origin the bytes already read followed by whatever the client still sends past the limit.
	req.Body = io.NopCloser(io.MultiReader(&bodyBuffer, clientBody))
	return bodyBytes, nil
}

// armBodyReadDeadline starts the appsecBodyReadTimeoutSeconds timer for a body of unknown length and
// returns it. A declared length returns nil and keeps Traefik's readTimeout.
func (c *Client) armBodyReadDeadline(req clientrequest.Request, responseController *http.ResponseController) *time.Timer {
	if !isBodyLengthUnknown(req.Request) {
		return nil
	}
	clientBody := req.Body
	return time.AfterFunc(time.Duration(c.bodyReadTimeoutSeconds)*time.Second, func() {
		cutClientBodyRead(clientBody, responseController)
	})
}

// cutClientBodyRead ends the in-flight client body read. The controller reaches HTTP/1.1 and HTTP/2;
// Close (the fallback when there is no controller or it refuses the deadline) reaches only HTTP/2 and HTTP/3.
func cutClientBodyRead(clientBody io.Closer, responseController *http.ResponseController) {
	if responseController != nil && responseController.SetReadDeadline(time.Now()) == nil {
		return
	}
	_ = clientBody.Close()
}

// bodyReadDeadlineFired reports whether the body-read deadline timer already fired. It stops a timer
// that has not fired. A nil timer (declared length, no deadline) never fired.
func bodyReadDeadlineFired(deadlineTimer *time.Timer) bool {
	if deadlineTimer == nil {
		return false
	}
	return !deadlineTimer.Stop()
}

// drainResponse consumes leftover bytes so the AppSec HTTP connection can be reused.
func (c *Client) drainResponse(res *http.Response) {
	if _, errDrain := io.Copy(io.Discard, res.Body); errDrain != nil {
		c.log.Debug("appsecQuery:drainBody", "error", errDrain)
	}
	if errClose := res.Body.Close(); errClose != nil {
		c.log.Error("appsecQuery:closeBody", "error", errClose)
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
		log.Debug("appsecQuery:parseBody", "error", parseErr)
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

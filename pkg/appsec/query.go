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
	"strconv"
	"time"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/admission"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/clientrequest"
	configuration "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/wafhop"
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

// ErrClientDisconnected is wafhop.ErrClientDisconnected: the client left while its body was buffered.
// Query MUST NOT call AppSec or apply FailureAction; the bouncer stops without a ban.
var ErrClientDisconnected = wafhop.ErrClientDisconnected

// ErrClientBodyRead is wafhop.ErrClientBodyRead: any other failure reading the client body.
// Query does not call AppSec and does not apply FailureAction; the bouncer answers 400 without a ban.
var ErrClientBodyRead = wafhop.ErrClientBodyRead

// ErrBodyReadTimeout is wafhop.ErrBodyReadTimeout: a body without Content-Length did not arrive within
// appsecBodyReadTimeoutSeconds. Query does not call AppSec and does not apply FailureAction; the bouncer
// answers 400 whatever the failure action says.
var ErrBodyReadTimeout = wafhop.ErrBodyReadTimeout

// ErrGateSkip is a denied AppSec admission. Query MUST NOT call AppSec or apply FailureAction.
var ErrGateSkip = errors.New("appsecQuery:unhealthySkip")

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

// isMethodWithForwardableBody reports whether a client body on this method is copied to AppSec.
func isMethodWithForwardableBody(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

// Query forwards the request to this AppSec HTTP client.
// The status table in the body is the CrowdSec AppSec protocol this method follows.
//
// The body is read before admission, so a client error never holds a ticket the gate waits on.
// ctrl is the inbound request's response controller: a body without Content-Length is read under
// appsecBodyReadTimeoutSeconds, and ctrl cuts that read when the deadline fires (nil falls back to
// closing the body, which cuts HTTP/2 only).
func (c *Client) Query(req clientrequest.Request, pol Policy, ctrl *http.ResponseController) (*Response, error) {
	appsecReq, err := c.newAppsecForwardRequest(req, ctrl)
	if err != nil {
		return nil, err
	}
	ticket, admitErr := c.admitAppsecHop(req)
	if errors.Is(admitErr, ErrClientDisconnected) {
		return nil, admitErr
	}
	if admitErr != nil {
		return resultForFailureAction(pol.FailureAction, "appsecQuery:admission")
	}
	if !ticket.Admitted {
		return nil, ErrGateSkip
	}

	current := c.currentTransport()
	if current == nil || current.httpClient == nil {
		c.log.Error("appsecQuery:unreachable")
		c.gate.Record(ticket, false)
		return resultForFailureAction(pol.FailureAction, "appsecQuery:unreachable")
	}
	res, err := current.httpClient.Do(appsecReq)
	if err != nil {
		if wafhop.IsInboundCanceled(req.Request, err) {
			return nil, ErrClientDisconnected
		}
		c.log.Error("appsecQuery:unreachable", "error", err)
		c.gate.Record(ticket, false)
		return resultForFailureAction(pol.FailureAction, "appsecQuery:unreachable: "+err.Error())
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
		logger.Debounced(c.log, slog.LevelInfo, 5*time.Second, "appsecQuery:failure", "statusCode", res.StatusCode)
		c.gate.Record(ticket, false)
		return resultForFailureAction(pol.FailureAction, "appsecQuery statusCode:500")
	}
	if res.StatusCode == http.StatusUnauthorized {
		logger.Debounced(c.log, slog.LevelWarn, 5*time.Second, msgUnauthenticated)
		// The listener answered: a wrong key is a configuration error, not an outage, so it does
		// not spend the gate budget and FailureAction keeps applying on every request.
		c.gate.Record(ticket, true)
		return resultForFailureAction(pol.FailureAction, "appsecQuery statusCode:401")
	}
	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusForbidden {
		logger.Debounced(c.log, slog.LevelWarn, 5*time.Second, msgUnexpectedListenerStatus, "statusCode", res.StatusCode)
		c.gate.Record(ticket, false)
		return resultForFailureAction(pol.FailureAction, fmt.Sprintf("appsecQuery statusCode:%d", res.StatusCode))
	}

	body, err := c.readCappedAppsecBody(res)
	if err != nil {
		// Io errors use FailureAction; oversized bodies stay as dest (allow 200 / error otherwise).
		if errors.Is(err, errAppsecReadBody) {
			c.log.Info("appsecQuery:failure", "error", err)
			c.gate.Record(ticket, false)
			return resultForFailureAction(pol.FailureAction, err.Error())
		}
		return nil, err
	}
	c.gate.Record(ticket, true)
	// Only 200 and 403 reach here. interpretAppsecBody turns a missing action into allow or a ban.
	decision, err := interpretAppsecBody(res.StatusCode, body, c.log)
	if err != nil {
		return nil, err
	}
	return decision, nil
}

// admitAppsecHop consults the Gate. An unadmitted ticket is a skip. Cancel does not Report.
func (c *Client) admitAppsecHop(req clientrequest.Request) (admission.Ticket, error) {
	ticket, allowErr := c.gate.Admit(req.Context())
	if allowErr != nil {
		if wafhop.IsInboundCanceled(req.Request, allowErr) {
			return admission.Ticket{}, ErrClientDisconnected
		}
		c.log.Error("fail to admit AppSec request", "error", allowErr)
		return admission.Ticket{}, allowErr
	}
	return ticket, nil
}

// newAppsecForwardRequest builds the AppSec listener request, copying client headers and identity.
func (c *Client) newAppsecForwardRequest(req clientrequest.Request, ctrl *http.ResponseController) (*http.Request, error) {
	routeURL := url.URL{
		Scheme: c.appsecScheme,
		Host:   c.appsecHost,
		Path:   c.appsecPath,
	}
	appsecReq, err := c.newAppsecBodyRequest(routeURL.String(), req.Request, ctrl)
	if err != nil {
		return nil, err
	}
	// Omit hop-by-hop headers (Transfer-Encoding among them) and the client Content-Length;
	// the length is rebuilt below from the bytes actually forwarded.
	wafhop.CopyEndToEndHeaders(appsecReq.Header, req.Header, "Content-Length")
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

// newAppsecBodyRequest chooses POST (copied client body, with or without Content-Length) or GET (no
// body, or a method whose body is not forwarded) toward AppSec. The original verb always travels on
// X-Crowdsec-Appsec-Verb.
func (c *Client) newAppsecBodyRequest(target string, httpReq *http.Request, ctrl *http.ResponseController) (*http.Request, error) {
	switch {
	case wafhop.HasBody(httpReq) && isMethodWithForwardableBody(httpReq.Method):
		// AppSec forwards the first appsecBodyLimit bytes; the rest still reaches origin.
		bodyBytes, err := wafhop.ReadBody(httpReq, c.appsecBodyLimit, wafhop.TruncateAtLimit, ctrl, c.bodyReadTimeout)
		if err != nil {
			return nil, err
		}
		req, _ := http.NewRequest(http.MethodPost, target, bytes.NewReader(bodyBytes))
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

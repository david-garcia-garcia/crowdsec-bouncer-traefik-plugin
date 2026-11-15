package bouncer

import (
	"errors"
	"net/http"
	"strings"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/appsec"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/clientrequest"
	configuration "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/httprule"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/lapi"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

// originAppsec is the usage-metrics origin of a remediation an AppSec verdict decided.
const originAppsec = "appsec"

// crowdsecChallengeCallbackPrefix is the CrowdSec 1.8 bot-detection script and submit path prefix.
// AppSec must answer these paths: an unanswered result is 404, never origin, and a relay here is not a new drop.
const crowdsecChallengeCallbackPrefix = "/crowdsec-internal/challenge/"

// serveAppSec reports whether AppSec or a captcha rule wrote the response.
// A cleared captcha gate or a widget asset did not write. False means ServeHTTP calls next.
// When AppSec is in use and nothing wrote, the challenge prefix gets 404 so origin is not called.
func (b *Bouncer) serveAppSec(rw http.ResponseWriter, req clientrequest.Request, match httprule.ActionMatch) bool {
	if b.answerAppSec(rw, req, match) {
		return true
	}
	// Nothing answered (allow, failure-action passthrough, or a cleared captcha gate):
	// the challenge prefix still must not reach origin.
	if !match.SkipAppsec && b.subscribeAppSec && isCrowdsecChallengeCallbackPath(req.URL.Path) {
		http.NotFound(rw, req.Request)
		return true
	}
	return false
}

// answerAppSec runs the captcha rule or AppSec for this request. True means the response was written.
func (b *Bouncer) answerAppSec(rw http.ResponseWriter, req clientrequest.Request, match httprule.ActionMatch) bool {
	if match.CaptchaName != "" {
		return b.applyCaptchaRuleServeHTTP(rw, req, match)
	}
	if match.SkipAppsec || !b.subscribeAppSec {
		return false
	}
	if b.applyAppsecServeHTTP(rw, req, match) {
		return true
	}
	// AppSec judged this request alone. A captcha form POST it let through is
	// still the answer to an earlier captcha, so the gate validates it.
	return b.isCaptchaFormAnswer(req) && b.serveAppsecCaptchaGate(rw, req)
}

// applyAppsecServeHTTP runs this router's AppSec check.
// True means the response was written. A missing client uses the AppSec failure action.
// A query that must not continue writes that remediation. False means the caller may continue.
func (b *Bouncer) applyAppsecServeHTTP(rw http.ResponseWriter, req clientrequest.Request, match httprule.ActionMatch) bool {
	appsecClient := b.loadedAppSec()
	if appsecClient == nil {
		switch b.appsecFailureAction {
		case configuration.FailureActionPassthrough:
			return false
		case configuration.FailureActionCaptcha:
			return b.handleRemediationServeHTTP(rw, req, decisionscope.CaptchaValue, lapi.OriginPluginAppsecFailure)
		default:
			b.warnCaptchaSuperseded(req, match)
			b.handleBanServeHTTP(rw, req, configuration.ReasonAPPSEC, headerReasonAppsecFailure, lapi.OriginPluginAppsecFailure)
			return true
		}
	}
	pol := appsec.Policy{
		FailureAction: b.appsecFailureAction,
	}
	decision, err := appsecClient.Query(req, pol)
	if errors.Is(err, appsec.ErrClientDisconnected) {
		b.handleClientDisconnectedServeHTTP(rw, req)
		return true
	}
	if errors.Is(err, appsec.ErrClientBodyRead) {
		b.handleClientBodyReadServeHTTP(rw, req, err)
		return true
	}
	if errors.Is(err, appsec.ErrFailureCaptcha) {
		return b.handleRemediationServeHTTP(rw, req, decisionscope.CaptchaValue, lapi.OriginPluginAppsecFailure)
	}
	if err != nil {
		b.log.Debug("applyAppsecServeHTTP", "ip", req.IPAddrString(), "isWaf", true, "error", err)
		b.warnCaptchaSuperseded(req, match)
		b.handleBanServeHTTP(rw, req, configuration.ReasonAPPSEC, headerReasonAppsecFailure, lapi.OriginPluginAppsecFailure)
		return true
	}
	if decision == nil || decision.Action == "" || decision.Action == appsec.ActionAllow {
		return false
	}
	switch decision.Action {
	case appsec.ActionBan:
		b.warnCaptchaSuperseded(req, match)
		b.handleBanStatusServeHTTP(rw, req, configuration.ReasonAPPSEC, headerReasonAppsec, originAppsec, b.appsecBanStatusCode(decision))
		return true
	case appsec.ActionCaptcha:
		// CrowdSec sends captcha without a page: the bouncer renders its own captcha.
		if match.CaptchaName != "" {
			return false
		}
		return b.serveAppsecCaptchaGate(rw, req)
	case appsec.ActionChallenge:
		if decision.UserBodyContent == "" {
			b.warnCaptchaSuperseded(req, match)
			b.handleBanServeHTTP(rw, req, configuration.ReasonAPPSEC, headerReasonAppsecChallengeEmpty, originAppsec)
			return true
		}
		if match.CaptchaName != "" {
			return false
		}
	default:
		// An action this bouncer cannot render, with no page to relay, must not become an empty page.
		if decision.UserBodyContent == "" {
			b.warnCaptchaSuperseded(req, match)
			b.handleBanServeHTTP(rw, req, configuration.ReasonAPPSEC, headerReasonAppsecActionEmpty, originAppsec)
			return true
		}
	}
	b.handleAppsecResponseServeHTTP(rw, req, decision)
	return true
}

// appsecBanStatusCode is the client status for an AppSec ban.
// CrowdSec always sends http_status on a ban: 429 for RateLimit(), the SetReturnCode() or
// user_blocked_http_code value, else 403. A value from 200 to 599 is relayed as is.
// Zero, missing, or out-of-range values keep bouncerRemediationStatusCode.
func (b *Bouncer) appsecBanStatusCode(decision *appsec.Response) int {
	if decision.HTTPStatus >= http.StatusOK && decision.HTTPStatus <= 599 {
		return decision.HTTPStatus
	}
	return b.remediationStatusCode
}

// handleAppsecResponseServeHTTP writes a structured AppSec envelope (challenge HTML, cookies, headers) to the client.
func (b *Bouncer) handleAppsecResponseServeHTTP(rw http.ResponseWriter, req clientrequest.Request, decision *appsec.Response) {
	// Challenge scripts and submit are the same solve as the page; do not count them as extra drops.
	if !isCrowdsecChallengeCallbackPath(req.URL.Path) {
		b.recordDropped(req, originAppsec, "")
	}

	// Copy AppSec-supplied headers, skipping hop-by-hop names and Set-Cookie (cookies have their own field).
	for name, values := range decision.UserHeaders {
		if isHopByHopHeader(name) || strings.EqualFold(name, "Set-Cookie") {
			continue
		}
		rw.Header()[http.CanonicalHeaderKey(name)] = values
	}
	for _, cookie := range decision.UserCookies {
		rw.Header().Add("Set-Cookie", cookie)
	}
	if b.remediationCustomHeader != "" {
		if value := formatAppsecRelayHeader(decision.Action); value != "" {
			rw.Header().Set(b.remediationCustomHeader, value)
		}
	}
	if rw.Header().Get("Content-Type") == "" && b.banTemplateContentType != "" {
		rw.Header().Set("Content-Type", b.banTemplateContentType)
	}

	status := decision.HTTPStatus
	if status == 0 {
		status = http.StatusOK
	}
	if status < 100 || status > 999 {
		status = b.remediationStatusCode
	}

	rw.WriteHeader(status)

	if req.Method == http.MethodHead || decision.UserBodyContent == "" {
		return
	}
	if _, err := rw.Write([]byte(decision.UserBodyContent)); err != nil {
		b.log.Warn("handleAppsecResponseServeHTTP could not write appsec response", "ip", req.IPAddrString(), "error", err)
	}
}

// isHopByHopHeader reports names that must not be copied from AppSec onto the client response.
func isHopByHopHeader(name string) bool {
	switch http.CanonicalHeaderKey(name) {
	case "Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Te", "Trailers", "Transfer-Encoding", "Upgrade":
		return true
	default:
		return false
	}
}

// isCrowdsecChallengeCallbackPath reports script and submit paths under /crowdsec-internal/challenge/.
func isCrowdsecChallengeCallbackPath(path string) bool {
	return strings.HasPrefix(path, crowdsecChallengeCallbackPrefix)
}

// handleClientDisconnectedServeHTTP sets the client-disconnected remediation header.
// It does not ban and does not call next. The caller returns so ServeHTTP stops.
func (b *Bouncer) handleClientDisconnectedServeHTTP(rw http.ResponseWriter, req clientrequest.Request) {
	logger.Trace(b.log, "client disconnected while buffering AppSec body", "ip", req.IPAddrString())
	if b.remediationCustomHeader != "" {
		if value := formatRemediationHeader(headerKindError, headerReasonClientDisconnected, ""); value != "" {
			rw.Header().Set(b.remediationCustomHeader, value)
		}
	}
}

// handleClientBodyReadServeHTTP answers 400 when the client body could not be read whole for
// AppSec and the client is still connected (for example the server read timeout on a slow HTTP/2
// upload). Not a ban: no ban template, no dropped metrics, no origin, no FailureAction.
func (b *Bouncer) handleClientBodyReadServeHTTP(rw http.ResponseWriter, req clientrequest.Request, err error) {
	b.log.Debug("client body read failed while buffering AppSec body", "ip", req.IPAddrString(), "error", err)
	if b.remediationCustomHeader != "" {
		if value := formatRemediationHeader(headerKindError, headerReasonClientBodyRead, ""); value != "" {
			rw.Header().Set(b.remediationCustomHeader, value)
		}
	}
	http.Error(rw, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
}

package bouncer

import (
	"net/http"
	"strings"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/appsec"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/clientrequest"
	configuration "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/httprule"
)

// answerAppsecVerdict writes the response for the verdict Query returned.
// True means the response was written. False means allow, or a captcha or challenge verdict
// that a matched captcha action rule answers instead, and the caller may continue.
func (b *Bouncer) answerAppsecVerdict(rw http.ResponseWriter, req clientrequest.Request, match httprule.ActionMatch, decision *appsec.Response) bool {
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
			b.banAppsecVerdict(rw, req, match, headerReasonAppsecChallengeEmpty)
			return true
		}
		if match.CaptchaName != "" {
			return false
		}
	default:
		// An action this bouncer cannot render, with no page to relay, must not become an empty page.
		if decision.UserBodyContent == "" {
			b.banAppsecVerdict(rw, req, match, headerReasonAppsecActionEmpty)
			return true
		}
	}
	// A challenge, or an unknown action, that carries a page: relay it.
	b.handleAppsecResponseServeHTTP(rw, req, decision)
	return true
}

// banAppsecVerdict writes a ban an AppSec verdict decided, with bouncerRemediationStatusCode.
// When a captcha action rule also matched, it warns that the rule lost.
func (b *Bouncer) banAppsecVerdict(rw http.ResponseWriter, req clientrequest.Request, match httprule.ActionMatch, headerReason string) {
	b.banWarnCaptchaRule(rw, req, match, configuration.ReasonAPPSEC, headerReason, originAppsec)
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

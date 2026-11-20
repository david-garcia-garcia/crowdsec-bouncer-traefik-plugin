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
	return b.isCaptchaFormAnswer(req) && b.serveAppsecCaptchaGate(rw, req, match)
}

// applyAppsecServeHTTP runs this router's AppSec check.
// True means the response was written. A missing client uses the AppSec failure action.
// A query that must not continue writes that remediation. False means the caller may continue.
func (b *Bouncer) applyAppsecServeHTTP(rw http.ResponseWriter, req clientrequest.Request, match httprule.ActionMatch) bool {
	appsecClient := b.loadedAppSec()
	if appsecClient == nil {
		return b.applyAppsecFailureAction(rw, req, match)
	}
	decision, err := appsecClient.Query(req, appsec.Policy{FailureAction: b.appsecFailureAction})
	if err != nil {
		return b.answerAppsecQueryError(rw, req, match, err)
	}
	return b.answerAppsecVerdict(rw, req, match, decision)
}

// applyAppsecFailureAction applies this router's AppSec failure action when no AppSec client is published.
// A listener failure does not come here: Query applies the action and answerAppsecQueryError writes its result.
// False means the response was not written, and the caller may continue.
func (b *Bouncer) applyAppsecFailureAction(rw http.ResponseWriter, req clientrequest.Request, match httprule.ActionMatch) bool {
	switch b.appsecFailureAction {
	case configuration.FailureActionPassthrough:
		return false
	case configuration.FailureActionCaptcha:
		return b.captchaAppsecFailure(rw, req, match)
	default:
		b.banAppsecFailure(rw, req, match)
		return true
	}
}

// answerAppsecQueryError writes the response for an error from Query.
// Query already applied the failure action: passthrough is not an error, captcha is ErrFailureCaptcha,
// and every other error is a ban. A client that left or sent a broken body is not a ban.
// False means a captcha kind did not write.
func (b *Bouncer) answerAppsecQueryError(rw http.ResponseWriter, req clientrequest.Request, match httprule.ActionMatch, err error) bool {
	switch {
	case errors.Is(err, appsec.ErrClientDisconnected):
		b.handleClientDisconnectedServeHTTP(rw, req)
		return true
	case errors.Is(err, appsec.ErrClientBodyRead):
		b.handleClientBodyReadServeHTTP(rw, req, err)
		return true
	case errors.Is(err, appsec.ErrFailureCaptcha):
		return b.captchaAppsecFailure(rw, req, match)
	default:
		b.log.Debug("applyAppsecServeHTTP", "ip", req.IPAddrString(), "isWaf", true, "error", err)
		b.banAppsecFailure(rw, req, match)
		return true
	}
}

// captchaAppsecFailure serves the captcha gate for the AppSec failure action.
// False means a widget asset, a cleared gate, or a bypassCaptcha rule, and the caller continues.
func (b *Bouncer) captchaAppsecFailure(rw http.ResponseWriter, req clientrequest.Request, match httprule.ActionMatch) bool {
	if b.bypassesCaptcha(req, match) {
		return false
	}
	return b.handleRemediationServeHTTP(rw, req, decisionscope.CaptchaValue, lapi.OriginPluginAppsecFailure)
}

// banAppsecFailure writes the ban for an AppSec failure. When a captcha action rule also matched, it warns that the rule lost.
func (b *Bouncer) banAppsecFailure(rw http.ResponseWriter, req clientrequest.Request, match httprule.ActionMatch) {
	b.banWarnCaptchaRule(rw, req, match, configuration.ReasonAPPSEC, headerReasonAppsecFailure, lapi.OriginPluginAppsecFailure)
}

// isCrowdsecChallengeCallbackPath reports script and submit paths under /crowdsec-internal/challenge/.
func isCrowdsecChallengeCallbackPath(path string) bool {
	return strings.HasPrefix(path, crowdsecChallengeCallbackPrefix)
}

// handleClientDisconnectedServeHTTP sets the client-disconnected remediation header.
// It does not ban and does not call next. The caller returns so ServeHTTP stops.
func (b *Bouncer) handleClientDisconnectedServeHTTP(rw http.ResponseWriter, req clientrequest.Request) {
	logger.Trace(b.log, "client disconnected while buffering AppSec body", "ip", req.IPAddrString())
	b.setRemediationHeader(rw, headerKindError, headerReasonClientDisconnected, "")
}

// handleClientBodyReadServeHTTP answers 400 when the client body could not be read whole for
// AppSec and the client is still connected (for example the server read timeout on a slow HTTP/2
// upload). Not a ban: no ban template, no dropped metrics, no origin, no FailureAction.
func (b *Bouncer) handleClientBodyReadServeHTTP(rw http.ResponseWriter, req clientrequest.Request, err error) {
	b.log.Debug("client body read failed while buffering AppSec body", "ip", req.IPAddrString(), "error", err)
	b.setRemediationHeader(rw, headerKindError, headerReasonClientBodyRead, "")
	http.Error(rw, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
}

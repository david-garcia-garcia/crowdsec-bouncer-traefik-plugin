package bouncer

import (
	"net/http"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/clientrequest"
	configuration "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/httprule"
)

// msgBackOffStricterThanFailure is the startup WARN when a leg answers a backoff more strictly than a failure.
const msgBackOffStricterThanFailure = "crowdsec bouncer backoff action stricter than failure action"

// applyBackOffAction answers a gate skip (LAPI live/none, AppSec, or ModSec) with this router's
// backoff action for that leg. passthrough writes nothing; captcha serves the router's captcha gate
// (ban:captcha-downgrade without a usable client); ban writes the ban page and warns when a captcha
// action rule lost. banReason, headerReason (<leg>-backoff), and origin (the leg's failure origin)
// label the answer. False means nothing was written, and the caller continues.
func (b *Bouncer) applyBackOffAction(rw http.ResponseWriter, req clientrequest.Request, match httprule.ActionMatch, action, banReason, headerReason, origin string) bool {
	switch action {
	case configuration.FailureActionPassthrough:
		return false
	case configuration.FailureActionCaptcha:
		return b.captchaUnlessBypassed(rw, req, match, banReason, headerReason, origin)
	default:
		b.banWarnCaptchaRule(rw, req, match, banReason, headerReason, origin)
		return true
	}
}

// warnStricterBackOffActions logs one WARN per subscribed gated leg whose backoff action ranks above
// its failure action (passthrough < captcha < ban). It never fails New. A router that opens LAPI
// itself in stream or alone does not warn for LAPI: those modes build no gate. A pure LAPI subscriber
// cannot see the owner's mode, so it warns.
func (b *Bouncer) warnStricterBackOffActions(config *configuration.Config, subscriptions Subscriptions) {
	if subscriptions.LAPI && !opensPolledLAPI(config) {
		b.warnStricterBackOffAction("lapi", b.lapiFailureAction, b.lapiBackOffAction)
	}
	if subscriptions.AppSec {
		b.warnStricterBackOffAction("appsec", b.appsecFailureAction, b.appsecBackOffAction)
	}
	if subscriptions.ModSec {
		b.warnStricterBackOffAction("modsec", b.modsecFailureAction, b.modsecBackOffAction)
	}
}

// warnStricterBackOffAction logs the stricter-than WARN for one leg when backOffAction outranks failureAction.
func (b *Bouncer) warnStricterBackOffAction(leg, failureAction, backOffAction string) {
	if actionSeverity(backOffAction) <= actionSeverity(failureAction) {
		return
	}
	b.log.Warn(msgBackOffStricterThanFailure, "leg", leg, "failureAction", failureAction, "backOffAction", backOffAction)
}

// opensPolledLAPI reports whether this router opens LAPI itself in stream or alone mode.
func opensPolledLAPI(config *configuration.Config) bool {
	return config.LapiEnabled && (config.LapiMode == configuration.StreamMode || config.LapiMode == configuration.AloneMode)
}

// actionSeverity ranks a failure or backoff action: passthrough 0, captcha 1, ban 2.
func actionSeverity(action string) int {
	switch action {
	case configuration.FailureActionBan:
		return 2
	case configuration.FailureActionCaptcha:
		return 1
	default:
		return 0
	}
}

package bouncer

import (
	"net/http"

	captcha "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/captcha"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/clientrequest"
	configuration "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/httprule"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/lapi"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

const msgCaptchaUnsubscribed = "crowdsec bouncer captcha unsubscribed"

// usableCaptcha is this router's captcha client when it can serve the gate: subscribed, published, and Valid.
// Nil means a captcha here is a downgrade ban.
func (b *Bouncer) usableCaptcha() *captcha.Client {
	if !b.captchaLeg.subscribed {
		return nil
	}
	captchaClient := b.loadedCaptcha()
	if captchaClient == nil || !captchaClient.Valid {
		return nil
	}
	return captchaClient
}

// isCaptchaFormAnswer reports whether req is a challenge-form POST this router's captcha gate can answer.
func (b *Bouncer) isCaptchaFormAnswer(req clientrequest.Request) bool {
	captchaClient := b.usableCaptcha()
	return captchaClient != nil && captchaClient.HasChallengeMarker(req.Request)
}

// applyCaptchaRuleServeHTTP queries AppSec unless this rule skips it, then serves the captcha gate when AppSec did not write.
// False means the gate did not write, and ServeHTTP calls next.
func (b *Bouncer) applyCaptchaRuleServeHTTP(rw http.ResponseWriter, req clientrequest.Request, match httprule.ActionMatch) bool {
	if !match.SkipAppsec && b.appsecLeg.subscribed && b.applyAppsecServeHTTP(rw, req, match) {
		return true
	}
	return b.handleRemediationServeHTTP(rw, req, decisionscope.CaptchaValue, lapi.OriginPluginRules(match.CaptchaName))
}

// bypassesCaptcha reports whether a bypassCaptcha action rule matched, so this request gets no captcha.
// A caller that would serve the captcha gate returns false instead, as for a cleared gate: nothing is
// written and the request continues. TRACE only: the condition is client-driven.
func (b *Bouncer) bypassesCaptcha(req clientrequest.Request, match httprule.ActionMatch) bool {
	if match.BypassCaptchaName == "" {
		return false
	}
	logger.Trace(b.log, "bypassCaptcha", "ip", req.IPAddrString(), "name", match.BypassCaptchaName)
	return true
}

// serveAppsecCaptchaGate serves this router's captcha gate for AppSec: a captcha verdict, or a captcha form POST AppSec let through.
// False means a widget asset, a cleared gate, or a bypassCaptcha rule, and the caller continues.
func (b *Bouncer) serveAppsecCaptchaGate(rw http.ResponseWriter, req clientrequest.Request, match httprule.ActionMatch) bool {
	if b.bypassesCaptcha(req, match) {
		return false
	}
	return b.handleCaptchaKindServeHTTP(rw, req, configuration.ReasonAPPSEC, headerReasonAppsec, originAppsec)
}

// handleCaptchaKindServeHTTP writes a challenge, a solved-form redirect, or a downgrade ban.
// Parameters follow handleBanServeHTTP: banReason is the ban template reason on a downgrade, headerReason names the challenge page.
// False means a widget asset or a cleared gate, and the caller continues.
func (b *Bouncer) handleCaptchaKindServeHTTP(rw http.ResponseWriter, req clientrequest.Request, banReason, headerReason, origin string) bool {
	if !b.captchaLeg.subscribed {
		b.log.Warn(msgCaptchaUnsubscribed, "leg", "captcha", "instanceName", b.captchaLeg.instanceName)
		b.handleBanServeHTTP(rw, req, banReason, headerReasonCaptchaDowngrade, origin)
		return true
	}
	captchaClient := b.usableCaptcha()
	if captchaClient == nil {
		b.handleBanServeHTTP(rw, req, banReason, headerReasonCaptchaDowngrade, origin)
		return true
	}

	// Same-origin widget assets must load while the visitor is still unsolved.
	if captchaClient.IsCustomResourceRequest(req.Request) {
		return false
	}

	// A valid gate cookie plus the challenge marker is a second-tab submit, not origin traffic.
	if captchaClient.Check(req) {
		if captchaClient.HasChallengeMarker(req.Request) {
			captchaClient.WriteSolvedRedirect(rw, req.Request, b.remediationCustomHeader)
			return true
		}
		return false
	}

	b.recordDropped(req, origin, "captcha")
	challengeValue := formatRemediationHeader(headerKindCaptcha, headerReason, origin)
	captchaClient.ServeHTTP(rw, req, b.remediationCustomHeader, challengeValue)
	return true
}

// warnCaptchaSuperseded logs when a captcha rule lost to a ban from another leg.
func (b *Bouncer) warnCaptchaSuperseded(req clientrequest.Request, match httprule.ActionMatch) {
	if match.CaptchaName == "" {
		return
	}
	b.log.Warn("warnCaptchaSuperseded", "ip", req.IPAddrString(), "name", match.CaptchaName)
}

// remediateUnderActionRules writes kind and origin as the matched action rules allow.
// When kind is a ban and a captcha action rule also matched, it warns that the rule lost.
// When kind is a captcha and a bypassCaptcha rule matched, it writes nothing.
// False means a captcha kind did not write: a widget asset, a cleared gate, or a bypassCaptcha rule.
func (b *Bouncer) remediateUnderActionRules(rw http.ResponseWriter, req clientrequest.Request, match httprule.ActionMatch, kind, origin string) bool {
	switch decisionscope.RemediationKind(kind) {
	case decisionscope.BannedValue:
		b.warnCaptchaSuperseded(req, match)
	case decisionscope.CaptchaValue:
		if b.bypassesCaptcha(req, match) {
			return false
		}
	}
	return b.handleRemediationServeHTTP(rw, req, kind, origin)
}

// banWarnCaptchaRule writes a ban. When a captcha action rule also matched, it warns that the rule lost.
func (b *Bouncer) banWarnCaptchaRule(rw http.ResponseWriter, req clientrequest.Request, match httprule.ActionMatch, reason, headerReason, origin string) {
	b.warnCaptchaSuperseded(req, match)
	b.handleBanServeHTTP(rw, req, reason, headerReason, origin)
}

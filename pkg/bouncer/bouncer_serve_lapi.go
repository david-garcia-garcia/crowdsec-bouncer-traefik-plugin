package bouncer

import (
	"net/http"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/clientrequest"
	configuration "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/httprule"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/lapi"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

// serveLAPI reports whether LAPI wrote the response.
// False means ServeHTTP continues with AppSec. A cleared captcha gate, a widget asset, and a captcha
// on a request a bypassCaptcha rule matched do not write.
func (b *Bouncer) serveLAPI(rw http.ResponseWriter, req clientrequest.Request, match httprule.ActionMatch) bool {
	if match.SkipLapi || !b.lapiLeg.subscribed {
		return false
	}
	lapiClient := b.loadedLAPI()
	if lapiClient == nil {
		return b.applyLapiFailureAction(rw, req, match, configuration.ReasonLAPI, lapi.OriginPluginLapiFailure)
	}
	crowdsecMode := lapiClient.Mode()

	// Mapped scope headers for this request. Missing headers are omitted.
	scopes := decisionscope.RequestScopeValues(b.decisionScopeHeaders, req.Request)

	// live, stream, and alone consult the cache.
	if crowdsecMode == configuration.LiveMode || crowdsecMode == configuration.StreamMode || crowdsecMode == configuration.AloneMode {
		kind, origin, originID, lookupErr := lapiClient.LookupRemediation(req.IPAddrString(), req.IPAddr(), scopes)
		if lookupErr != nil {
			// Only the Redis engine fails a lookup. Any failure (down, timeout, auth, TLS) gets this router's
			// Redis failure action; passthrough skips the LAPI leg and does not fall through to LiveLookup.
			b.log.Error("serveLAPI:Get", "ip", req.IPAddrString(), "failureAction", b.lapiRedisFailureAction, "error", lookupErr)
			return b.applyFailureAction(rw, req, match, b.lapiRedisFailureAction, configuration.ReasonTECH, lapi.OriginPluginTechCacheFail)
		}
		kind, origin = b.appliedLAPIRemediation(match, kind, origin, originID)
		switch {
		case decisionscope.IsActiveRemediation(kind):
			logger.Trace(b.log, "serveLAPI", appendScopesGroup([]any{"ip", req.IPAddrString(), "remediation", kind}, scopes)...)
			return b.remediateUnderActionRules(rw, req, match, kind, b.resolveDroppedOrigin(origin, originID))
		case kind == decisionscope.NoBannedValue:
			return false
		}
	}

	if crowdsecMode == configuration.StreamMode || crowdsecMode == configuration.AloneMode {
		if lapiClient.StreamHealthy() {
			// No decision affecting this IP.
			return false
		}
		logger.Trace(b.log, "serveLAPI", "isCrowdsecStreamHealthy", false, "ip", req.IPAddrString())
		// Stream/alone never query LAPI per request. Miss is allow or failure action.
		return b.applyLapiFailureAction(rw, req, match, configuration.ReasonTECH, lapi.OriginPluginTechStreamFail)
	}

	if crowdsecMode == configuration.LiveMode || crowdsecMode == configuration.NoneMode {
		kind, origin, lookupErr := lapiClient.LiveLookup(req.IPAddrString(), scopes, b.defaultDecisionSeconds)
		if lookupErr != nil {
			b.log.Debug("serveLAPI:LiveLookup", "error", lookupErr.Error())
			if !decisionscope.IsActiveRemediation(kind) {
				return b.applyLapiFailureAction(rw, req, match, configuration.ReasonLAPI, lapi.OriginPluginLapiFailure)
			}
		}
		kind, origin = b.appliedLAPIRemediation(match, kind, origin, 0)
		if kind == decisionscope.NoBannedValue {
			return false
		}
		logger.Trace(b.log, "serveLAPI:LiveLookup", appendScopesGroup([]any{"ip", req.IPAddrString(), "isBanned", kind}, scopes)...)
		return b.remediateUnderActionRules(rw, req, match, kind, origin)
	}
	return true
}

// applyLapiFailureAction applies this router's LAPI failure action.
// Callers are a missing subscribed client, a live lookup error, and an unhealthy stream miss.
// False means the response was not written, and ServeHTTP continues with AppSec.
func (b *Bouncer) applyLapiFailureAction(rw http.ResponseWriter, req clientrequest.Request, match httprule.ActionMatch, banReason, origin string) bool {
	return b.applyFailureAction(rw, req, match, b.lapiFailureAction, banReason, origin)
}

// applyFailureAction applies passthrough, captcha, or ban (any other value) for a LAPI-leg failure.
func (b *Bouncer) applyFailureAction(rw http.ResponseWriter, req clientrequest.Request, match httprule.ActionMatch, action, banReason, origin string) bool {
	switch action {
	case configuration.FailureActionPassthrough:
		return false
	case configuration.FailureActionCaptcha:
		return b.remediateUnderActionRules(rw, req, match, decisionscope.CaptchaValue, origin)
	default:
		b.banWarnCaptchaRule(rw, req, match, banReason, headerReasonFromOrigin(origin), origin)
		return true
	}
}

// resolveDroppedOrigin returns origin when it is set.
// Otherwise it asks the published LAPI client for the name of originID.
func (b *Bouncer) resolveDroppedOrigin(origin string, originID uint16) string {
	if origin != "" {
		return origin
	}
	if originID == 0 {
		return ""
	}
	if client := b.loadedLAPI(); client != nil {
		return client.OriginName(originID)
	}
	return ""
}

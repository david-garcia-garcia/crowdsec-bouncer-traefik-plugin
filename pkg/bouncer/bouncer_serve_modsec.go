package bouncer

import (
	"errors"
	"net/http"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/clientrequest"
	configuration "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/httprule"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/lapi"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/modsecurity"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/wafhop"
)

// legModsec names the ModSec leg in client-body logs.
const legModsec = "modsec"

// originModsec is the usage-metrics origin of a block the CRS sidecar decided.
const originModsec = "modsec"

// serveModSec runs the CRS sidecar inspect after LAPI and AppSec. True means the response was written.
// False means allow, a gate skip, or a failure action that lets the request through: ServeHTTP calls next.
func (b *Bouncer) serveModSec(rw http.ResponseWriter, req clientrequest.Request, match httprule.ActionMatch) bool {
	if match.SkipModsec || !b.subscribeModsec {
		return false
	}
	client := b.loadedModSec()
	if client == nil {
		return b.applyModsecFailureAction(rw, req, match)
	}
	blocked, err := client.Inspect(req.Request, b.modsecFailureAction)
	switch {
	case err == nil && blocked == nil:
		return false
	case err == nil:
		b.recordDropped(req, originModsec, "ban")
		b.setRemediationHeader(rw, headerKindBan, headerReasonModsec, "")
		modsecurity.WriteBlock(rw, blocked)
		return true
	case errors.Is(err, modsecurity.ErrGateSkip):
		// The admission gate is backing off: the sidecar was not called and the failure action does not apply.
		return false
	case errors.Is(err, modsecurity.ErrBodyTooLarge):
		b.log.Debug("serveModSec: request body over modsecBodyLimit", "ip", req.IPAddrString())
		http.Error(rw, "Request body too large", http.StatusRequestEntityTooLarge)
		return true
	case errors.Is(err, wafhop.ErrClientDisconnected):
		b.handleClientDisconnectedServeHTTP(rw, req, legModsec)
		return true
	case errors.Is(err, wafhop.ErrClientBodyRead):
		b.handleClientBodyReadServeHTTP(rw, req, legModsec, err)
		return true
	default:
		b.log.Debug("serveModSec: no sidecar verdict", "ip", req.IPAddrString(), "error", err)
		return b.applyModsecFailureAction(rw, req, match)
	}
}

// applyModsecFailureAction applies bouncerModsecFailureAction when the sidecar gave no verdict
// or no ModSec client is published. False means passthrough, a captcha gate the client cleared,
// or a bypassCaptcha rule.
func (b *Bouncer) applyModsecFailureAction(rw http.ResponseWriter, req clientrequest.Request, match httprule.ActionMatch) bool {
	switch b.modsecFailureAction {
	case configuration.FailureActionPassthrough:
		return false
	case configuration.FailureActionCaptcha:
		return b.captchaModsecFailure(rw, req, match)
	default:
		b.banWarnCaptchaRule(rw, req, match, configuration.ReasonMODSEC, headerReasonModsecFailure, lapi.OriginPluginModsecFailure)
		return true
	}
}

// captchaModsecFailure serves the captcha gate for the ModSec failure action.
// False means a widget asset, a cleared gate, or a bypassCaptcha rule, and the caller continues.
func (b *Bouncer) captchaModsecFailure(rw http.ResponseWriter, req clientrequest.Request, match httprule.ActionMatch) bool {
	if b.bypassesCaptcha(req, match) {
		return false
	}
	return b.handleRemediationServeHTTP(rw, req, decisionscope.CaptchaValue, lapi.OriginPluginModsecFailure)
}

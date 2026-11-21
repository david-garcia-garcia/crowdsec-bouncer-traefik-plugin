package bouncer

import (
	"html"
	"net/http"
	"strconv"
	"time"

	captcha "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/captcha"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/clientrequest"
	configuration "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

// noLAPIDecisionEnd is the decisionLeft a ban with no LAPI decision behind it passes (AppSec,
// ModSecurity, failure actions, the cache-failure ban, action rules). It never sets Retry-After.
const noLAPIDecisionEnd time.Duration = 0

// handleRemediationServeHTTP writes captcha or ban for kind.
// True means the response was written. A captcha kind returns false for a widget asset or a cleared gate.
// decisionLeft is the time left on the LAPI decision behind kind, or noLAPIDecisionEnd.
//
// Captcha kind serves a challenge only when this router subscribed and the
// client is usable (every method, HEAD included). Unsubscribed captcha kind
// WARNs crowdsec bouncer captcha unsubscribed then handleBanServeHTTP.
func (b *Bouncer) handleRemediationServeHTTP(rw http.ResponseWriter, req clientrequest.Request, remediation, origin string, decisionLeft time.Duration) bool {
	kind := decisionscope.RemediationKind(remediation)
	logger.Trace(b.log, "handleRemediationServeHTTP", "ip", req.IPAddrString(), "remediation", kind)
	if kind == decisionscope.CaptchaValue {
		return b.handleCaptchaKindServeHTTP(rw, req, configuration.ReasonLAPI, headerReasonFromOrigin(origin), origin, decisionLeft)
	}
	b.handleBanServeHTTP(rw, req, configuration.ReasonLAPI, headerReasonFromOrigin(origin), origin, decisionLeft)
	return true
}

// handleBanServeHTTP writes the operator ban template for this client with bouncerRemediationStatusCode.
func (b *Bouncer) handleBanServeHTTP(rw http.ResponseWriter, req clientrequest.Request, reason, headerReason, origin string, decisionLeft time.Duration) {
	b.handleBanStatusServeHTTP(rw, req, reason, headerReason, origin, b.remediationStatusCode, decisionLeft)
}

// handleBanStatusServeHTTP writes the operator ban template for this client with statusCode.
// A 429 with a known LAPI decision end (decisionLeft > 0) also carries Retry-After.
func (b *Bouncer) handleBanStatusServeHTTP(rw http.ResponseWriter, req clientrequest.Request, reason, headerReason, origin string, statusCode int, decisionLeft time.Duration) {
	b.recordDropped(req, origin, "ban")

	b.setRemediationHeader(rw, headerKindBan, headerReason, origin)
	rw.Header().Set("Content-Type", b.banTemplateContentType)
	rw.Header().Set("Cache-Control", "no-cache, no-store")
	if statusCode == http.StatusTooManyRequests && decisionLeft > 0 {
		rw.Header().Set("Retry-After", retryAfterSeconds(decisionLeft))
	}
	rw.WriteHeader(statusCode)
	if b.banTemplate == nil || req.Method == http.MethodHead || !statusAllowsBody(statusCode) {
		return
	}
	templateData := map[string]string{
		"RemediationReason": reason,
		"ClientIP":          req.IPAddrString(),
		"Domain":            html.EscapeString(captcha.RequestDomain(req.Host)),
	}

	if b.traceCustomHeader != "" {
		headerValue := req.Header.Get(b.traceCustomHeader)
		templateData["TraceID"] = trustedTraceID(headerValue)
	}

	err := b.banTemplate.Execute(rw, templateData)
	if err != nil {
		b.log.Warn("handleBanServeHTTP could not write template to ResponseWriter", "error", err)
	}
}

// retryAfterSeconds is decisionLeft as RFC 9110 delay-seconds: whole seconds rounded up, at least 1.
func retryAfterSeconds(decisionLeft time.Duration) string {
	seconds := int64((decisionLeft + time.Second - 1) / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	return strconv.FormatInt(seconds, 10)
}

// statusAllowsBody reports whether net/http lets a response with statusCode carry a body.
func statusAllowsBody(statusCode int) bool {
	return statusCode != http.StatusNoContent && statusCode != http.StatusNotModified
}

// recordDropped counts a remediating response on the connection usage-metrics window, both the request and the byte series.
func (b *Bouncer) recordDropped(req clientrequest.Request, origin, remediation string) {
	if client := b.loadedLAPI(); client != nil {
		client.IncDropped(origin, req.IPType(), remediation)
		client.IncDroppedBytes(origin, req.IPType(), req.EstimatedSize())
	}
}

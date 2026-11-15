package bouncer

import (
	"html"
	"net/http"

	captcha "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/captcha"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/clientrequest"
	configuration "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

// handleRemediationServeHTTP writes captcha or ban for kind.
// True means the response was written. A captcha kind returns false for a widget asset or a cleared gate.
//
// Captcha kind serves a challenge only when this router subscribed and the
// client is usable (every method, HEAD included). Unsubscribed captcha kind
// WARNs crowdsec bouncer captcha unsubscribed then handleBanServeHTTP.
func (b *Bouncer) handleRemediationServeHTTP(rw http.ResponseWriter, req clientrequest.Request, remediation, origin string) bool {
	kind := decisionscope.RemediationKind(remediation)
	logger.Trace(b.log, "handleRemediationServeHTTP", "ip", req.IPAddrString(), "remediation", kind)
	if kind == decisionscope.CaptchaValue {
		return b.handleCaptchaKindServeHTTP(rw, req, configuration.ReasonLAPI, headerReasonFromOrigin(origin), origin)
	}
	b.handleBanServeHTTP(rw, req, configuration.ReasonLAPI, headerReasonFromOrigin(origin), origin)
	return true
}

// handleBanServeHTTP writes the operator ban template for this client with bouncerRemediationStatusCode.
func (b *Bouncer) handleBanServeHTTP(rw http.ResponseWriter, req clientrequest.Request, reason, headerReason, origin string) {
	b.handleBanStatusServeHTTP(rw, req, reason, headerReason, origin, b.remediationStatusCode)
}

// handleBanStatusServeHTTP writes the operator ban template for this client with statusCode.
func (b *Bouncer) handleBanStatusServeHTTP(rw http.ResponseWriter, req clientrequest.Request, reason, headerReason, origin string, statusCode int) {
	b.recordDropped(req, origin, "ban")

	if b.remediationCustomHeader != "" {
		if value := formatRemediationHeader(headerKindBan, headerReason, origin); value != "" {
			rw.Header().Set(b.remediationCustomHeader, value)
		}
	}
	rw.Header().Set("Content-Type", b.banTemplateContentType)
	rw.Header().Set("Cache-Control", "no-cache, no-store")
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

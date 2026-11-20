package bouncer

import (
	"net/http"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/clientrequest"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

// Answers shared by the WAF legs (AppSec, ModSec) when the client body could not be buffered.
// Neither is a WAF verdict nor a WAF failure, so neither bans nor uses the leg's fallback.

// handleClientDisconnectedServeHTTP sets the client-disconnected remediation header.
// It does not ban and does not call next. The caller returns so ServeHTTP stops.
func (b *Bouncer) handleClientDisconnectedServeHTTP(rw http.ResponseWriter, req clientrequest.Request, leg string) {
	logger.Trace(b.log, "client disconnected while buffering the request body", "ip", req.IPAddrString(), "leg", leg)
	b.setRemediationHeader(rw, headerKindError, headerReasonClientDisconnected, "")
}

// handleClientBodyReadServeHTTP answers 400 when the client body could not be read whole and the
// client is still connected (for example the server read timeout on a slow HTTP/2 upload).
// Not a ban: no ban template, no dropped metrics, no origin, no leg fallback.
func (b *Bouncer) handleClientBodyReadServeHTTP(rw http.ResponseWriter, req clientrequest.Request, leg string, err error) {
	b.log.Debug("client body read failed while buffering the request body", "ip", req.IPAddrString(), "leg", leg, "error", err)
	b.setRemediationHeader(rw, headerKindError, headerReasonClientBodyRead, "")
	http.Error(rw, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
}

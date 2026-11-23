package bouncer

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/clientrequest"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

// Answers shared by the WAF legs (AppSec, ModSec) when the client body could not be buffered.
// None is a WAF verdict nor a WAF failure, so none bans nor uses the leg's fallback.

// WARN lines for a body without Content-Length that did not arrive within the leg's read timeout.
// Each is debounced on its own text, so each leg logs at most once per window.
const (
	msgAppsecBodyReadTimeout = "AppSec request body not received within appsecBodyReadTimeoutSeconds; request blocked. Exclude streaming routes with a bouncerActionRules bypassAppsec (or bypass) rule"
	msgModsecBodyReadTimeout = "ModSec request body not received within modsecBodyReadTimeoutSeconds; request blocked. Exclude streaming routes with a bouncerActionRules bypassModsec (or bypass) rule"
)

// bodyReadTimeoutWarnWindow is the debounce window of the body read deadline WARN.
const bodyReadTimeoutWarnWindow = 5 * time.Second

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

// handleBodyReadTimeoutServeHTTP answers 400 when a body without Content-Length did not arrive within
// the leg's read timeout, whatever the leg's failure action says: no ban template, no dropped metrics,
// no leg fallback, and next is not called. warning is that leg's debounced WARN; it names the request
// by path only, so a query string never reaches the log.
func (b *Bouncer) handleBodyReadTimeoutServeHTTP(rw http.ResponseWriter, req clientrequest.Request, leg, warning string, timeoutSeconds int64) {
	logger.Debounced(b.log, slog.LevelWarn, bodyReadTimeoutWarnWindow, warning,
		"ip", req.IPAddrString(), "leg", leg, "method", req.Method, "host", req.Host, "path", req.URL.Path, "timeoutSeconds", timeoutSeconds)
	b.setRemediationHeader(rw, headerKindError, headerReasonBodyReadTimeout, "")
	http.Error(rw, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
}

package bouncer

import (
	"errors"
	"net/http"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/clientrequest"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/httprule"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/modsecurity"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/wafhop"
)

// legModsec names the ModSec leg in the shared WAF-leg logs.
const legModsec = "modsec"

// serveModSec reports whether ModSec wrote the response.
// False means ServeHTTP calls next. A skipped or unsubscribed leg does not write.
func (b *Bouncer) serveModSec(rw http.ResponseWriter, req clientrequest.Request, match httprule.ActionMatch) bool {
	if match.SkipModsec || !b.subscribeModsec {
		return false
	}
	client := b.loadedModSec()
	if client == nil {
		return modsecurity.ApplyFailMode(rw, b.modsecFailMode)
	}
	wrote, err := client.Inspect(rw, req.Request, b.modsecFailMode, b.remediationCustomHeader)
	switch {
	case errors.Is(err, wafhop.ErrClientDisconnected):
		b.handleClientDisconnectedServeHTTP(rw, req, legModsec)
		return true
	case errors.Is(err, wafhop.ErrClientBodyRead):
		b.handleClientBodyReadServeHTTP(rw, req, legModsec, err)
		return true
	}
	return wrote
}

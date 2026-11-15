package bouncer

import (
	"net/http"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/clientrequest"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/httprule"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/modsecurity"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/reclaim"
)

// loadedModSec is the ModSec client this route has stored, or nil.
func (b *Bouncer) loadedModSec() *modsecurity.Client {
	stored := reclaim.Unbox(&b.modsecBound)
	client, _ := stored.(*modsecurity.Client)
	return client
}

// ReceiveModSec stores the published ModSec client and traces the pointer change.
// published is a reclaim.Published. The same pointer is a no-op.
func (b *Bouncer) ReceiveModSec(published any) {
	if !b.subscribeModsec {
		return
	}
	notice, _ := published.(reclaim.Published)
	b.storeBinding(&b.modsecBound, notice.Value)
	b.receiveModSec()
}

// receiveModSec traces a ModSec bind or unbind.
func (b *Bouncer) receiveModSec() {
	current := b.loadedModSec()
	b.bindingMu.Lock()
	defer b.bindingMu.Unlock()
	if b.modsecReceiveSeen && current == b.modsecReceived {
		return
	}
	previous := b.modsecReceived
	b.modsecReceived = current
	b.modsecReceiveSeen = true
	if previous != nil && previous != current {
		b.traceBouncerBinding(false, "modsec", b.modsecInstanceName, previous.Incarnation())
	}
	if current == nil {
		if previous == nil {
			b.traceBouncerBinding(false, "modsec", b.modsecInstanceName, "")
		}
		return
	}
	b.traceBouncerBinding(true, "modsec", b.modsecInstanceName, current.Incarnation())
}

// serveModSec reports whether ModSec wrote the response.
// False means ServeHTTP calls next. A skipped or unsubscribed leg does not write.
func (b *Bouncer) serveModSec(rw http.ResponseWriter, req clientrequest.Request, match httprule.ActionMatch) bool {
	if match.SkipModsec || !b.subscribeModsec {
		return false
	}
	client := b.loadedModSec()
	if client == nil {
		return b.applyModsecFailMode(rw)
	}
	return client.Inspect(rw, req.Request, b.modsecFailMode, b.remediationCustomHeader)
}

// applyModsecFailMode writes empty HTTP 502 when failMode is close. Open continues.
func (b *Bouncer) applyModsecFailMode(rw http.ResponseWriter) bool {
	if b.modsecFailMode == configuration.ModsecFailModeClose {
		http.Error(rw, "", http.StatusBadGateway)
		return true
	}
	return false
}

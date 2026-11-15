package bouncer

import (
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

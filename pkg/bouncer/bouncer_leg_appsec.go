package bouncer

import (
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/appsec"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/reclaim"
)

// loadedAppSec is the AppSec client this route has stored, or nil.
func (b *Bouncer) loadedAppSec() *appsec.Client {
	stored := reclaim.Unbox(&b.appsecBound)
	client, _ := stored.(*appsec.Client)
	return client
}

// ReceiveAppSec stores the published AppSec client and traces the pointer change.
// published is a reclaim.Published. The same pointer is a no-op.
func (b *Bouncer) ReceiveAppSec(published any) {
	if !b.subscribeAppSec {
		return
	}
	notice, _ := published.(reclaim.Published)
	b.storeBinding(&b.appsecBound, notice.Value)
	b.receiveAppSec()
}

// receiveAppSec traces an AppSec bind or unbind.
func (b *Bouncer) receiveAppSec() {
	current := b.loadedAppSec()
	b.bindingMu.Lock()
	defer b.bindingMu.Unlock()
	if b.appsecReceiveSeen && current == b.appsecReceived {
		return
	}
	previous := b.appsecReceived
	b.appsecReceived = current
	b.appsecReceiveSeen = true
	if previous != nil && previous != current {
		b.traceBouncerBinding(false, "appsec", b.appsecInstanceName, previous.Incarnation())
	}
	if current == nil {
		if previous == nil {
			b.traceBouncerBinding(false, "appsec", b.appsecInstanceName, "")
		}
		return
	}
	b.traceBouncerBinding(true, "appsec", b.appsecInstanceName, current.Incarnation())
}

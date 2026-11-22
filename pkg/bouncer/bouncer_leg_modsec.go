package bouncer

import (
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/modsecurity"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/reclaim"
)

// loadedModSec is the ModSec client this route has stored, or nil.
func (b *Bouncer) loadedModSec() *modsecurity.Client {
	stored := reclaim.Unbox(&b.modsecLeg.bound)
	client, _ := stored.(*modsecurity.Client)
	return client
}

// ReceiveModSec stores the published ModSec client and traces the pointer change.
// published is a reclaim.Published. The same pointer is a no-op.
func (b *Bouncer) ReceiveModSec(published any) {
	b.receiveBinding(&b.modsecLeg, published, func() string { return b.loadedModSec().Incarnation() }, nil, nil)
}

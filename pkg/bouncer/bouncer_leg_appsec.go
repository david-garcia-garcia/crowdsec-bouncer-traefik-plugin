package bouncer

import (
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/appsec"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/reclaim"
)

// loadedAppSec is the AppSec client this route has stored, or nil.
func (b *Bouncer) loadedAppSec() *appsec.Client {
	stored := reclaim.Unbox(&b.appsecLeg.bound)
	client, _ := stored.(*appsec.Client)
	return client
}

// ReceiveAppSec stores the published AppSec client and traces the pointer change.
// published is a reclaim.Published. The same pointer is a no-op.
func (b *Bouncer) ReceiveAppSec(published any) {
	b.receiveBinding(&b.appsecLeg, published, func() string { return b.loadedAppSec().Incarnation() }, nil)
}

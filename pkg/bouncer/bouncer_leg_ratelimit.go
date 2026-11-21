package bouncer

import (
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/ratelimit"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/reclaim"
)

// loadedRateLimit is the rate-limit client this route has stored, or nil while its owner is unpublished.
func (b *Bouncer) loadedRateLimit() *ratelimit.Client {
	client, _ := reclaim.Unbox(&b.rateLimitLeg.bound).(*ratelimit.Client)
	return client
}

// ReceiveRateLimit stores the published rate-limit client and traces the pointer change.
// published is a reclaim.Published. The same pointer is a no-op.
func (b *Bouncer) ReceiveRateLimit(published any) {
	b.receiveBinding(&b.rateLimitLeg, published, func() string { return b.loadedRateLimit().Incarnation() }, nil)
}

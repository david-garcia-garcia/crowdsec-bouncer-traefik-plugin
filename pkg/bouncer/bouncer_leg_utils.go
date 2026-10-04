package bouncer

import (
	"sync/atomic"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/reclaim"
)

// storeBinding publishes value as a new immutable *reclaim.Box.
// Never assign Box.Value in place: concurrent Unbox reads that field without sync.
func (b *Bouncer) storeBinding(dest *atomic.Value, value any) {
	dest.Store(&reclaim.Box{Value: value})
}

// traceBouncerBinding records whether this route bound or released the named backend.
// An empty incarnation is omitted, which is the case where nothing was bound before.
func (b *Bouncer) traceBouncerBinding(bound bool, leg, instanceName, incarnation string) {
	msg := "crowdsec bouncer unbound"
	if bound {
		msg = "crowdsec bouncer bound"
	}
	attrs := []any{
		"traefikName", b.name,
		"leg", leg,
		"instanceName", instanceName,
	}
	if incarnation != "" {
		attrs = append(attrs, "incarnation", incarnation)
	}
	logger.Trace(b.log, msg, attrs...)
}

package bouncer

import (
	"sync/atomic"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/reclaim"
)

// legBinding is this route's side of one published leg: whether it subscribes, the Client
// Watch last stored, and the incarnation it last traced as bound or unbound.
// Not generic and no interface-typed received Client: Yaegi v0.16 cannot run either shape.
type legBinding struct {
	bound             atomic.Value // *reclaim.Box holding the leg's Client, or its typed nil
	subscribed        bool         // bouncerEnabled plus the leg's instance name
	leg               string       // trace "leg" attr, the plugin's reclaim group for this leg
	instanceName      string
	tracedIncarnation string // incarnation of the last traced Client; empty when that Client was nil
	traceSeen         bool   // a bind or unbind was traced at least once
}

// receiveBinding stores published (a reclaim.Published) as binding's new Box when this route
// subscribes to the leg, then traces the bind or unbind it caused.
// loadIncarnation reads the stored Client back; onBind (nil skips) runs before a bound trace.
func (b *Bouncer) receiveBinding(binding *legBinding, published any, loadIncarnation func() string, onBind func()) {
	if !binding.subscribed {
		return
	}
	notice, _ := published.(reclaim.Published)
	b.storeBinding(&binding.bound, notice.Value)
	b.traceBinding(binding, loadIncarnation(), onBind)
}

// traceBinding traces the move from the last traced Client to current (its incarnation, empty for nil).
// The same incarnation is a no-op. Replacing A by B traces unbound A, then bound B.
func (b *Bouncer) traceBinding(binding *legBinding, current string, onBind func()) {
	b.bindingMu.Lock()
	defer b.bindingMu.Unlock()
	if binding.traceSeen && current == binding.tracedIncarnation {
		return
	}
	previous := binding.tracedIncarnation
	binding.tracedIncarnation = current
	binding.traceSeen = true

	// Release the previous Client, if any.
	if previous != "" && previous != current {
		b.traceBouncerBinding(false, binding.leg, binding.instanceName, previous)
	}

	// Nothing bound now: an unbound line without incarnation only when nothing was bound before.
	if current == "" {
		if previous == "" {
			b.traceBouncerBinding(false, binding.leg, binding.instanceName, "")
		}
		return
	}

	// Bind the new Client.
	if onBind != nil {
		onBind()
	}
	b.traceBouncerBinding(true, binding.leg, binding.instanceName, current)
}

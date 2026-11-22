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
// loadIncarnation reads the stored Client back; onBind (nil skips) runs before a bound trace, and
// onUnbind (nil skips) after the trace of a move to no Client. Both run under bindingMu.
func (b *Bouncer) receiveBinding(binding *legBinding, published any, loadIncarnation func() string, onBind, onUnbind func()) {
	if !binding.subscribed {
		return
	}
	notice, _ := published.(reclaim.Published)
	b.storeBinding(&binding.bound, notice.Value)
	b.traceBinding(binding, loadIncarnation(), onBind, onUnbind)
}

// traceBinding traces the move from the last traced Client to the one whose incarnation is
// currentIncarnation (empty for nil). The same incarnation is a no-op. Replacing A by B traces unbound A,
// then bound B. onUnbind runs once per move to no Client: after a bound Client, or on a first empty delivery.
func (b *Bouncer) traceBinding(binding *legBinding, currentIncarnation string, onBind, onUnbind func()) {
	b.bindingMu.Lock()
	defer b.bindingMu.Unlock()
	if binding.traceSeen && currentIncarnation == binding.tracedIncarnation {
		return
	}
	previousIncarnation := binding.tracedIncarnation
	binding.tracedIncarnation = currentIncarnation
	binding.traceSeen = true

	// Release the previous Client, if any (the same incarnation returned above).
	if previousIncarnation != "" {
		b.traceBouncerBinding(false, binding.leg, binding.instanceName, previousIncarnation)
	}

	// Nothing bound now: an unbound line without incarnation only when nothing was bound before.
	if currentIncarnation == "" {
		if previousIncarnation == "" {
			b.traceBouncerBinding(false, binding.leg, binding.instanceName, "")
		}
		if onUnbind != nil {
			onUnbind()
		}
		return
	}

	// Bind the new Client.
	if onBind != nil {
		onBind()
	}
	b.traceBouncerBinding(true, binding.leg, binding.instanceName, currentIncarnation)
}

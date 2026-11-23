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
// loadIncarnation reads the stored Client back; onBind (nil skips) runs before a bound trace, under bindingMu.
func (b *Bouncer) receiveBinding(binding *legBinding, published any, loadIncarnation func() string, onBind func()) {
	if !binding.subscribed {
		return
	}
	notice, _ := published.(reclaim.Published)
	b.storeBinding(&binding.bound, notice.Value)
	b.traceBinding(binding, loadIncarnation(), onBind)
}

// traceBinding traces the move from the last traced Client to the one whose incarnation is
// currentIncarnation (empty for nil). The same incarnation is a no-op. Replacing A by B traces unbound A,
// then bound B. Each move to no Client (after a bound Client, or on a first empty delivery) logs the
// connection-unavailable WARN unless this router name and leg already have it pending, and a bind logs the
// INFO that answers a pending one (connectionWarnings), before onBind. Never per request.
func (b *Bouncer) traceBinding(binding *legBinding, currentIncarnation string, onBind func()) {
	b.bindingMu.Lock()
	defer b.bindingMu.Unlock()
	b.traceBindingLocked(binding, currentIncarnation, onBind)
}

// legBindings is every leg binding of this route, in a fixed order.
func (b *Bouncer) legBindings() []*legBinding {
	return []*legBinding{&b.lapiLeg, &b.appsecLeg, &b.captchaLeg, &b.modsecLeg, &b.rateLimitLeg}
}

// TraceUndeliveredBindings traces, as a delivery of no Client would, every subscribed leg Watch has delivered
// nothing to yet. Call it once, after the route's Watch calls. Compiled Go's Watch skips the first typed nil, so
// a name no middleware publishes (a typo, an owner not loaded yet) would otherwise log no connection-unavailable
// WARN; under Yaegi that delivery already happened and this is a no-op, so the WARN is never logged twice.
func (b *Bouncer) TraceUndeliveredBindings() {
	b.bindingMu.Lock()
	defer b.bindingMu.Unlock()
	for _, binding := range b.legBindings() {
		if binding.subscribed && !binding.traceSeen {
			b.traceBindingLocked(binding, "", nil)
		}
	}
}

// traceBindingLocked is traceBinding with bindingMu held.
func (b *Bouncer) traceBindingLocked(binding *legBinding, currentIncarnation string, onBind func()) {
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
		pendingConnectionWarnings.warnUnavailable(b.log, b.name, binding.leg, binding.instanceName)
		return
	}

	// Bind the new Client.
	pendingConnectionWarnings.answerAvailable(b.log, b.name, binding.leg, binding.instanceName, currentIncarnation)
	if onBind != nil {
		onBind()
	}
	b.traceBouncerBinding(true, binding.leg, binding.instanceName, currentIncarnation)
}

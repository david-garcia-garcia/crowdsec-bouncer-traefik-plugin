package bouncer

import (
	"strings"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/lapi"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/reclaim"
)

// loadedLAPI is the LAPI client this route has stored, or nil.
func (b *Bouncer) loadedLAPI() *lapi.Client {
	client, _ := reclaim.Unbox(&b.lapiBound).(*lapi.Client)
	return client
}

// ReceiveLAPI stores the published LAPI client and traces the pointer change.
// published is a reclaim.Published. The same pointer is a no-op.
func (b *Bouncer) ReceiveLAPI(published any) {
	if !b.subscribeLAPI {
		return
	}
	notice, _ := published.(reclaim.Published)
	b.storeBinding(&b.lapiBound, notice.Value)
	b.receiveLAPI()
}

// receiveLAPI traces a LAPI bind or unbind.
// A non-nil client also warns when a header scope is not in the stream.
func (b *Bouncer) receiveLAPI() {
	current := b.loadedLAPI()
	b.bindingMu.Lock()
	defer b.bindingMu.Unlock()
	if b.lapiReceiveSeen && current == b.lapiReceived {
		return
	}
	previous := b.lapiReceived
	b.lapiReceived = current
	b.lapiReceiveSeen = true
	if previous != nil && previous != current {
		b.traceBouncerBinding(false, "lapi", b.lapiInstanceName, previous.Incarnation())
	}
	if current == nil {
		if previous == nil {
			b.traceBouncerBinding(false, "lapi", b.lapiInstanceName, "")
		}
		return
	}
	missing := decisionscope.MissingStreamScopes(b.decisionScopeHeaders, current.StreamScopes())
	if len(missing) > 0 {
		b.log.Warn("crowdsec bouncer stream scopes missing",
			"traefikName", b.name,
			"missing", strings.Join(missing, ","),
		)
	}
	b.traceBouncerBinding(true, "lapi", b.lapiInstanceName, current.Incarnation())
}

// LapiClient is the bound LAPI backend this route uses, or nil.
func (b *Bouncer) LapiClient() *lapi.Client {
	return b.loadedLAPI()
}

// SameLapiClient reports whether two routes share one LAPI client pointer.
func (b *Bouncer) SameLapiClient(other *Bouncer) bool {
	return other != nil && b.loadedLAPI() == other.loadedLAPI()
}

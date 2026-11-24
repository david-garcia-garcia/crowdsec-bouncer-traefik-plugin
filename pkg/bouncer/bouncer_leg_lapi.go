package bouncer

import (
	"strings"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/lapi"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/reclaim"
)

// loadedLAPI is the LAPI client this route has stored, or nil.
func (b *Bouncer) loadedLAPI() *lapi.Client {
	client, _ := reclaim.Unbox(&b.lapiLeg.bound).(*lapi.Client)
	return client
}

// ReceiveLAPI stores the published LAPI client and traces the pointer change.
// published is a reclaim.Published. The same pointer is a no-op.
// A newly bound client also warns when a header scope is not in the stream.
func (b *Bouncer) ReceiveLAPI(published any) {
	b.receiveBinding(&b.lapiLeg, published, func() string { return b.loadedLAPI().Incarnation() }, b.warnMissingStreamScopes, nil)
}

// warnMissingStreamScopes warns when a decision scope header names a scope the bound LAPI client does not poll.
// Only stream and alone answer from the polled stream; live and none ask LAPI for each header scope per request.
// b.log already carries traefikName.
func (b *Bouncer) warnMissingStreamScopes() {
	client := b.loadedLAPI()
	if mode := client.Mode(); mode != configuration.StreamMode && mode != configuration.AloneMode {
		return
	}
	missing := decisionscope.MissingStreamScopes(b.decisionScopeHeaders, client.StreamScopes())
	if len(missing) > 0 {
		b.log.Warn("crowdsec bouncer stream scopes missing",
			"missing", strings.Join(missing, ","),
		)
	}
}

// LapiClient is the published LAPI client this route has stored, or nil.
func (b *Bouncer) LapiClient() *lapi.Client {
	return b.loadedLAPI()
}

// SameLapiClient reports whether two routes share one LAPI client pointer.
func (b *Bouncer) SameLapiClient(other *Bouncer) bool {
	return other != nil && b.loadedLAPI() == other.loadedLAPI()
}

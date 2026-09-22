package bouncer

import (
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/appsec"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/lapi"
)

func bindTestLAPI(b *Bouncer, client *lapi.Client, mode string) {
	b.subscribeLAPI = client != nil
	if client != nil {
		client.SetCrowdsecModeForTest(mode)
		b.lapiBound.Store(client)
		return
	}
	b.lapiBound.Store((*lapi.Client)(nil))
}

func bindTestAppSec(b *Bouncer, client *appsec.Client) {
	b.subscribeAppSec = client != nil
	if client != nil {
		b.appsecBound.Store(client)
		return
	}
	b.appsecBound.Store((*appsec.Client)(nil))
}

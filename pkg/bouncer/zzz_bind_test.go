package bouncer

import (
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/appsec"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/captcha"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/lapi"
)

func bindTestLAPI(b *Bouncer, client *lapi.Client) {
	b.subscribeLAPI = client != nil
	if client != nil {
		client.SetCrowdsecModeForTest(configuration.StreamMode)
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

func bindTestCaptcha(b *Bouncer, client *captcha.Client) {
	b.subscribeCaptcha = client != nil
	if client != nil {
		b.captchaBound.Store(client)
		return
	}
	b.captchaBound.Store((*captcha.Client)(nil))
}

package bouncer

import (
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/appsec"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/captcha"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/lapi"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/modsecurity"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/ratelimit"
)

func bindTestLAPI(b *Bouncer, client *lapi.Client) {
	b.lapiLeg.subscribed = client != nil
	if client != nil {
		client.SetCrowdsecModeForTest(configuration.StreamMode)
		b.lapiLeg.bound.Store(client)
		return
	}
	b.lapiLeg.bound.Store((*lapi.Client)(nil))
}

func bindTestAppSec(b *Bouncer, client *appsec.Client) {
	b.appsecLeg.subscribed = client != nil
	if client != nil {
		b.appsecLeg.bound.Store(client)
		return
	}
	b.appsecLeg.bound.Store((*appsec.Client)(nil))
}

func bindTestCaptcha(b *Bouncer, client *captcha.Client) {
	b.captchaLeg.subscribed = client != nil
	if client != nil {
		b.captchaLeg.bound.Store(client)
		return
	}
	b.captchaLeg.bound.Store((*captcha.Client)(nil))
}

func bindTestModSec(b *Bouncer, client *modsecurity.Client) {
	b.modsecLeg.subscribed = client != nil
	if client != nil {
		b.modsecLeg.bound.Store(client)
		return
	}
	b.modsecLeg.bound.Store((*modsecurity.Client)(nil))
}

// bindTestRateLimit subscribes b to client, or unsubscribes it when client is nil. It stores a Box as
// Watch does, so a later ReceiveRateLimit stores the same atomic.Value type.
func bindTestRateLimit(b *Bouncer, client *ratelimit.Client) {
	b.rateLimitLeg.subscribed = client != nil
	b.storeBinding(&b.rateLimitLeg.bound, client)
}

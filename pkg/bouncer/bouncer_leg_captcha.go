package bouncer

import (
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/captcha"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/reclaim"
)

// loadedCaptcha is the captcha client this route has stored, or nil.
func (b *Bouncer) loadedCaptcha() *captcha.Client {
	client, _ := reclaim.Unbox(&b.captchaLeg.bound).(*captcha.Client)
	return client
}

// ReceiveCaptcha stores the published captcha client and traces the pointer change.
// published is a reclaim.Published. The same pointer is a no-op.
func (b *Bouncer) ReceiveCaptcha(published any) {
	b.receiveBinding(&b.captchaLeg, published, func() string { return b.loadedCaptcha().Incarnation() }, nil)
}

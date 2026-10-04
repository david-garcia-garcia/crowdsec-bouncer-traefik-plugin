package bouncer

import (
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/captcha"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/reclaim"
)

// loadedCaptcha is the captcha client this route has stored, or nil.
func (b *Bouncer) loadedCaptcha() *captcha.Client {
	client, _ := reclaim.Unbox(&b.captchaBound).(*captcha.Client)
	return client
}

// ReceiveCaptcha stores the published captcha client and traces the pointer change.
// published is a reclaim.Published. The same pointer is a no-op.
func (b *Bouncer) ReceiveCaptcha(published any) {
	if !b.subscribeCaptcha {
		return
	}
	notice, _ := published.(reclaim.Published)
	b.storeBinding(&b.captchaBound, notice.Value)
	b.receiveCaptcha()
}

// receiveCaptcha traces a captcha bind or unbind.
func (b *Bouncer) receiveCaptcha() {
	current := b.loadedCaptcha()
	b.bindingMu.Lock()
	defer b.bindingMu.Unlock()
	if b.captchaReceiveSeen && current == b.captchaReceived {
		return
	}
	previous := b.captchaReceived
	b.captchaReceived = current
	b.captchaReceiveSeen = true
	if previous != nil && previous != current {
		b.traceBouncerBinding(false, "captcha", b.captchaInstanceName, previous.Incarnation())
	}
	if current == nil {
		if previous == nil {
			b.traceBouncerBinding(false, "captcha", b.captchaInstanceName, "")
		}
		return
	}
	b.traceBouncerBinding(true, "captcha", b.captchaInstanceName, current.Incarnation())
}

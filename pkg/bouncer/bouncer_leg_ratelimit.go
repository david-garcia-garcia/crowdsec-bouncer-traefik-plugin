package bouncer

import (
	configuration "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/ratelimit"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/reclaim"
)

// loadedRateLimit is the rate-limit client this route has stored, or nil while its owner is unpublished.
func (b *Bouncer) loadedRateLimit() *ratelimit.Client {
	client, _ := reclaim.Unbox(&b.rateLimitLeg.bound).(*ratelimit.Client)
	return client
}

// legRateLimit is the leg of the rate-limit binding, whose owner lines predate the shared connection lines.
const legRateLimit = "ratelimit"

const (
	// msgRateLimitOwnerUnavailable is the WARN line when this route's rate-limit owner stops being published:
	// every request now passes uncharged. connectionWarnings logs it in place of msgConnectionUnavailable.
	msgRateLimitOwnerUnavailable = "crowdsec bouncer rate limit owner unavailable"
	// msgRateLimitOwnerAvailable is the INFO line when a rate-limit client binds while this router name has a
	// msgRateLimitOwnerUnavailable pending (connectionWarnings).
	msgRateLimitOwnerAvailable = "crowdsec bouncer rate limit owner available"
)

// ReceiveRateLimit stores the published rate-limit client and traces the pointer change.
// published is a reclaim.Published. The same pointer is a no-op.
// A move to no client logs WARN once per outage of this router name, and the next bind of a router with that
// name, this Bouncer or one a reload rebuilt, logs INFO (traceBinding, connectionWarnings); a bind then runs
// the captcha check of logRateLimitCaptchaUnsubscribed.
func (b *Bouncer) ReceiveRateLimit(published any) {
	b.receiveBinding(&b.rateLimitLeg, published, func() string { return b.loadedRateLimit().Incarnation() }, b.logRateLimitCaptchaUnsubscribed)
}

// logRateLimitCaptchaUnsubscribed logs ERROR once per bind when the bound rate-limit client's policy can
// answer with a captcha and this route subscribes to no captcha, so each such answer will be downgraded.
// It runs on the bind, never on the request path.
func (b *Bouncer) logRateLimitCaptchaUnsubscribed() {
	if b.captchaLeg.subscribed || !rateLimitAnswersWithCaptcha(b.loadedRateLimit()) {
		return
	}
	b.log.Error(msgRateLimitCaptchaUnavailable,
		"reason", "unsubscribed", "instanceName", b.rateLimitLeg.instanceName)
}

// rateLimitAnswersWithCaptcha reports whether client's policy can answer with a captcha: a captcha bucket,
// or failure action captcha. False on a nil client.
func rateLimitAnswersWithCaptcha(client *ratelimit.Client) bool {
	if client == nil {
		return false
	}
	return client.Buckets().HasCaptchaBucket() || client.Policy().FailureAction == configuration.FailureActionCaptcha
}

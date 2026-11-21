package bouncer

import (
	"context"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	captcha "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/captcha"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/clientrequest"
	configuration "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/httprule"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/lapi"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/ratelimit"
)

const (
	// msgRateLimitExceeded is the INFO line for a log bucket over its limit.
	msgRateLimitExceeded = "crowdsec bouncer rate limit exceeded"
	// msgRateLimitCaptchaUnavailable is the ERROR line for a rate-limit captcha answer (a captcha bucket or
	// the failure action captcha) that this router can only give without a captcha.
	msgRateLimitCaptchaUnavailable = "crowdsec bouncer rate limit captcha unavailable"
	// msgRateLimitCaptchaDowngrade is the DEBUG line of each request whose rate-limit captcha answer was downgraded.
	msgRateLimitCaptchaDowngrade = "rateLimitCaptchaDowngrade"
	// rateLimitCaptchaUnusableInterval is how often the ERROR for a subscribed but unusable captcha may repeat.
	rateLimitCaptchaUnusableInterval = 5 * time.Second
)

// serveRateLimit charges req to the buckets of the rate-limit client this route subscribes to, under this
// route's own name, and answers with that client's policy. True means the response was written: a
// ratelimit bucket over its limit, a captcha bucket over its limit, or the failure action when the
// counter could not answer; or this router's captcha gate answering a challenge-form POST.
// False means the request continues to the AppSec step: no subscription or an unpublished owner, a
// bypassRateLimit rule, a widget asset of this router's captcha page, a challenge-form POST the gate did
// not answer, no bucket that answers, failure action passthrough, or a failure captcha that a cleared gate
// or a bypassCaptcha rule let through.
func (b *Bouncer) serveRateLimit(rw http.ResponseWriter, req clientrequest.Request, match httprule.ActionMatch) bool {
	rateLimitClient := b.loadedRateLimit()
	if rateLimitClient == nil || match.SkipRateLimit {
		return false
	}
	// The captcha page's own requests are not charged: widget assets continue, and the challenge-form
	// POST goes to the captcha gate when this policy can challenge.
	captchaClient := b.usableCaptcha()
	if captchaClient != nil && captchaClient.IsCustomResourceRequest(req.Request) {
		logger.Trace(b.log, "serveRateLimit", "ip", req.IPAddrString(), "captchaPage", true)
		return false
	}
	if b.isCaptchaFormAnswer(req) {
		logger.Trace(b.log, "serveRateLimit", "ip", req.IPAddrString(), "captchaForm", true)
		return b.answerRateLimitChallengeForm(rw, req, match, rateLimitClient)
	}
	buckets := rateLimitClient.Buckets()
	policy := rateLimitClient.Policy()
	// A client holding this router's valid captcha gate is not counted by captcha buckets.
	gateCleared := captchaClient != nil && buckets.HasCaptchaBucket() && captchaClient.Check(req)

	// One budget for every bucket and every Redis command of this request.
	ctx, cancel := context.WithTimeout(req.Context(), ratelimit.StepBudget)
	defer cancel()
	verdict := buckets.Charge(ctx, rateLimitClient, b.name, req.Request, req.IPAddr(), gateCleared)

	// Log buckets over their limit: the dry run exists to be read.
	for _, exceeded := range verdict.Exceeded {
		b.log.Info(msgRateLimitExceeded, "ip", req.IPAddrString(), "bucket", exceeded.Name,
			"requests", exceeded.Requests, "window", exceeded.Window.String())
	}

	// Answer by precedence: the counter error, then a ratelimit bucket, then a captcha bucket.
	if verdict.Err != nil {
		b.log.Debug("serveRateLimit", "ip", req.IPAddrString(), "error", verdict.Err)
		return b.applyRateLimitFailureAction(rw, req, match, policy.FailureAction, captchaClient)
	}
	if verdict.RateLimit.Name != "" {
		logger.Trace(b.log, "serveRateLimit", "ip", req.IPAddrString(), "bucket", verdict.RateLimit.Name)
		b.answerRateLimit(rw, req, match, verdict.RateLimit, policy)
		return true
	}
	if verdict.Captcha.Name != "" {
		logger.Trace(b.log, "serveRateLimit", "ip", req.IPAddrString(), "captchaBucket", verdict.Captcha.Name)
		return b.answerCaptchaBucket(rw, req, match, verdict.Captcha, policy, captchaClient)
	}
	return false
}

// answerRateLimitChallengeForm answers a challenge-form POST on a router with a usable captcha. No bucket
// charges it. When rateLimitClient's policy can answer with a captcha (a captcha bucket or failure action captcha),
// the POST answers a challenge this leg may have served, so this router's captcha gate validates it, as
// AppSec does for a form it let through: the solved redirect with the gate cookie, or the challenge page
// again with header captcha:ratelimit and drop origin plugin:ratelimit (no bucket answered).
// False means the request continues: a policy without a captcha answer, a bypassCaptcha rule, or a gate
// that did not write.
func (b *Bouncer) answerRateLimitChallengeForm(rw http.ResponseWriter, req clientrequest.Request, match httprule.ActionMatch, rateLimitClient *ratelimit.Client) bool {
	if !rateLimitAnswersWithCaptcha(rateLimitClient) || b.bypassesCaptcha(req, match) {
		return false
	}
	return b.handleCaptchaKindServeHTTP(rw, req, configuration.ReasonRateLimit, headerReasonRateLimit, lapi.OriginPluginRateLimitChallengeForm)
}

// answerRateLimit is the ratelimit answer for bucket: the ban page with the owner's status code,
// Retry-After when its policy says so, and header ban:ratelimit:<bucket>. When a captcha action rule also
// matched, it warns that the rule lost.
func (b *Bouncer) answerRateLimit(rw http.ResponseWriter, req clientrequest.Request, match httprule.ActionMatch, bucket ratelimit.AnsweringBucket, policy ratelimit.Policy) {
	b.warnCaptchaSuperseded(req, match)
	if policy.ResponseHeaders {
		rw.Header().Set("Retry-After", strconv.FormatInt(int64(bucket.RetryAfter/time.Second), 10))
	}
	b.handleBanStatusServeHTTP(rw, req, configuration.ReasonRateLimit, headerReasonRateLimit,
		lapi.OriginPluginRateLimit(bucket.Name), policy.StatusCode)
}

// answerCaptchaBucket answers for a captcha bucket over its limit with this router's challenge page
// (header captcha:ratelimit:<bucket>). It gives the ratelimit answer instead when a bypassCaptcha rule
// matched, so the limit does not become unlimited, or when captchaClient is nil (no usable captcha).
// False means the captcha gate did not write, and the request continues.
func (b *Bouncer) answerCaptchaBucket(rw http.ResponseWriter, req clientrequest.Request, match httprule.ActionMatch, bucket ratelimit.AnsweringBucket, policy ratelimit.Policy, captchaClient *captcha.Client) bool {
	origin := lapi.OriginPluginRateLimit(bucket.Name)
	if b.bypassesCaptcha(req, match) {
		b.answerRateLimit(rw, req, match, bucket, policy)
		return true
	}
	if captchaClient == nil {
		b.logRateLimitCaptchaDowngrade(req, origin)
		b.answerRateLimit(rw, req, match, bucket, policy)
		return true
	}
	return b.handleCaptchaKindServeHTTP(rw, req, configuration.ReasonRateLimit, headerReasonRateLimit, origin)
}

// applyRateLimitFailureAction applies the owner's failureAction when the counter errored, on this router.
// captchaClient is this router's usable captcha, or nil.
// False means the response was not written, and the request continues to the AppSec step.
func (b *Bouncer) applyRateLimitFailureAction(rw http.ResponseWriter, req clientrequest.Request, match httprule.ActionMatch, failureAction string, captchaClient *captcha.Client) bool {
	switch failureAction {
	case configuration.FailureActionPassthrough:
		return false
	case configuration.FailureActionCaptcha:
		return b.captchaRateLimitFailure(rw, req, match, captchaClient)
	default:
		b.banWarnCaptchaRule(rw, req, match, configuration.ReasonRateLimit, headerReasonRateLimitFailure, lapi.OriginPluginRateLimitFailure)
		return true
	}
}

// captchaRateLimitFailure serves the captcha gate for the rate-limit failure action. Without a usable
// captcha (captchaClient nil) it logs the downgrade like a captcha bucket does and writes the ban page
// with ban:captcha-downgrade.
// False means a cleared gate or a bypassCaptcha rule, and the caller continues.
func (b *Bouncer) captchaRateLimitFailure(rw http.ResponseWriter, req clientrequest.Request, match httprule.ActionMatch, captchaClient *captcha.Client) bool {
	if b.bypassesCaptcha(req, match) {
		return false
	}
	if captchaClient == nil {
		b.logRateLimitCaptchaDowngrade(req, lapi.OriginPluginRateLimitFailure)
		b.handleBanServeHTTP(rw, req, configuration.ReasonRateLimit, headerReasonCaptchaDowngrade, lapi.OriginPluginRateLimitFailure)
		return true
	}
	return b.handleCaptchaKindServeHTTP(rw, req, configuration.ReasonRateLimit, headerReasonRateLimitFailure, lapi.OriginPluginRateLimitFailure)
}

// logRateLimitCaptchaDowngrade logs a rate-limit captcha answer this router gives without a captcha:
// DEBUG on every such request, plus an ERROR at most every 5s when the router subscribes to a captcha
// that is unpublished or not valid. A router without a captcha subscription logged its ERROR once, when
// the rate-limit client bound (logRateLimitCaptchaUnsubscribed). It never warns msgCaptchaUnsubscribed.
func (b *Bouncer) logRateLimitCaptchaDowngrade(req clientrequest.Request, origin string) {
	reason := "unsubscribed"
	if b.captchaLeg.subscribed {
		reason = "unusable"
		logger.Debounced(b.log, slog.LevelError, rateLimitCaptchaUnusableInterval, msgRateLimitCaptchaUnavailable,
			"reason", reason, "instanceName", b.rateLimitLeg.instanceName,
			"captchaInstanceName", b.captchaLeg.instanceName)
	}
	b.log.Debug(msgRateLimitCaptchaDowngrade, "ip", req.IPAddrString(), "origin", origin, "reason", reason)
}

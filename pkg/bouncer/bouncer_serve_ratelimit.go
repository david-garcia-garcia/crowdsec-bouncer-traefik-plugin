package bouncer

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/clientrequest"
	configuration "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/httprule"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/lapi"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/ratelimit"
)

// msgRateLimitExceeded is the INFO line for a log bucket over its limit.
const msgRateLimitExceeded = "crowdsec bouncer rate limit exceeded"

// serveRateLimit charges req to the rate-limit buckets. True means the response was written: a deny
// bucket over its limit, or the failure action when the counter could not answer.
// False means the request continues to the AppSec step: no counter, a bypassRateLimit rule, no deny,
// failure action passthrough, or a failure captcha that a cleared gate or a bypassCaptcha rule let through.
func (b *Bouncer) serveRateLimit(rw http.ResponseWriter, req clientrequest.Request, match httprule.ActionMatch) bool {
	if b.rateLimitCounter == nil || b.rateLimitBuckets == nil || match.SkipRateLimit {
		return false
	}
	// One budget for every bucket and every Redis command of this request.
	ctx, cancel := context.WithTimeout(req.Context(), ratelimit.StepBudget)
	defer cancel()
	verdict := b.rateLimitBuckets.Charge(ctx, b.rateLimitCounter, b.name, req.Request, req.IPAddr())
	// Log buckets over their limit: the dry run exists to be read.
	for _, exceeded := range verdict.Exceeded {
		b.log.Info(msgRateLimitExceeded, "ip", req.IPAddrString(), "bucket", exceeded.Name,
			"requests", exceeded.Requests, "window", exceeded.Window.String())
	}
	if verdict.Err != nil {
		b.log.Debug("serveRateLimit", "ip", req.IPAddrString(), "error", verdict.Err)
		return b.applyRateLimitFailureAction(rw, req, match)
	}
	if verdict.DenyBucket == "" {
		return false
	}
	logger.Trace(b.log, "serveRateLimit", "ip", req.IPAddrString(), "bucket", verdict.DenyBucket)
	b.denyRateLimit(rw, req, match, verdict)
	return true
}

// denyRateLimit writes the ban page with rateLimitStatusCode and Retry-After for the denying bucket.
// When a captcha action rule also matched, it warns that the rule lost.
func (b *Bouncer) denyRateLimit(rw http.ResponseWriter, req clientrequest.Request, match httprule.ActionMatch, verdict ratelimit.Verdict) {
	b.warnCaptchaSuperseded(req, match)
	if b.rateLimitResponseHeaders {
		rw.Header().Set("Retry-After", strconv.FormatInt(int64(verdict.RetryAfter/time.Second), 10))
	}
	b.handleBanStatusServeHTTP(rw, req, configuration.ReasonRateLimit, headerReasonRateLimit,
		lapi.OriginPluginRateLimit(verdict.DenyBucket), b.rateLimitStatusCode)
}

// applyRateLimitFailureAction applies this router's rate-limit failure action when the counter errored.
// False means the response was not written, and the request continues to the AppSec step.
func (b *Bouncer) applyRateLimitFailureAction(rw http.ResponseWriter, req clientrequest.Request, match httprule.ActionMatch) bool {
	switch b.rateLimitFailureAction {
	case configuration.FailureActionPassthrough:
		return false
	case configuration.FailureActionCaptcha:
		if b.bypassesCaptcha(req, match) {
			return false
		}
		return b.handleCaptchaKindServeHTTP(rw, req, configuration.ReasonRateLimit, headerReasonRateLimitFailure, lapi.OriginPluginRateLimitFailure)
	default:
		b.banWarnCaptchaRule(rw, req, match, configuration.ReasonRateLimit, headerReasonRateLimitFailure, lapi.OriginPluginRateLimitFailure)
		return true
	}
}

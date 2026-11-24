package bouncer

import (
	"net/http"
	"strings"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/appsec"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/lapi"
)

// Closed header kind and reason tokens for bouncerRemediationHeadersCustomName.
const (
	headerKindBan     = "ban"
	headerKindCaptcha = "captcha"
	headerKindError   = "error"

	headerReasonLAPI                 = "lapi"
	headerReasonRules                = "rules"
	headerReasonLAPIFailure          = "lapi-failure"
	headerReasonLAPIBackoff          = "lapi-backoff"
	headerReasonStreamUnhealthy      = "stream-unhealthy"
	headerReasonCacheFail            = "cache-fail"
	headerReasonAppsec               = "appsec"
	headerReasonAppsecChallengeEmpty = "appsec-challenge-empty"
	headerReasonAppsecActionEmpty    = "appsec-action-empty"
	headerReasonAppsecFailure        = "appsec-failure"
	headerReasonAppsecBackoff        = "appsec-backoff"
	headerReasonRateLimit            = "ratelimit"
	headerReasonRateLimitFailure     = "ratelimit-failure"
	headerReasonModsec               = "modsec"
	headerReasonModsecFailure        = "modsec-failure"
	headerReasonModsecBackoff        = "modsec-backoff"
	headerReasonCaptchaDowngrade     = "captcha-downgrade"
	headerReasonChallenge            = "challenge"
	headerReasonClientDisconnected   = "client-disconnected"
	headerReasonClientBodyRead       = "client-body-read"

	listsHeaderPrefix = "lists_"
)

// formatRemediationHeader joins kind:reason, or kind:reason:third when the reason carries a third field
// and it is non-empty (headerThirdField). Empty kind or reason returns empty; it does not invent allow: pass.
func formatRemediationHeader(kind, reason, origin string) string {
	if kind == "" || reason == "" {
		return ""
	}
	if third := headerThirdField(reason, origin); third != "" {
		return kind + ":" + reason + ":" + third
	}
	return kind + ":" + reason
}

// headerThirdField is the third header field a reason carries: the encoded metrics origin for lapi, the
// bucket name (the origin after plugin:ratelimit:) for ratelimit, and none for the ratelimit origin without
// a bucket (plugin:ratelimit). Every other reason has none.
func headerThirdField(reason, origin string) string {
	switch reason {
	case headerReasonLAPI:
		return encodeHeaderOrigin(origin)
	case headerReasonRateLimit:
		if !strings.HasPrefix(origin, lapi.OriginPluginRateLimitPrefix) {
			return ""
		}
		return stripHeaderCtl(origin[len(lapi.OriginPluginRateLimitPrefix):])
	default:
		return ""
	}
}

// setRemediationHeader sets bouncerRemediationHeadersCustomName to kind:reason for this response.
// It does nothing when the operator did not name the header or the value is empty.
func (b *Bouncer) setRemediationHeader(rw http.ResponseWriter, kind, reason, origin string) {
	if b.remediationCustomHeader == "" {
		return
	}
	if value := formatRemediationHeader(kind, reason, origin); value != "" {
		rw.Header().Set(b.remediationCustomHeader, value)
	}
}

// encodeHeaderOrigin strips CR/LF/TAB and rewrites only the lists: prefix to lists_.
func encodeHeaderOrigin(origin string) string {
	origin = stripHeaderCtl(origin)
	if strings.HasPrefix(origin, listsOriginPrefix) {
		return listsHeaderPrefix + origin[len(listsOriginPrefix):]
	}
	return origin
}

// headerReasonFromOrigin maps a metrics origin to a closed header reason.
// Plugin origins stay a reason token. Every other origin is lapi (third field is that origin).
// A *-backoff reason is never derived here: a backoff answer shares its leg's failure origin, and
// the leg that answered the gate skip passes that reason to the writer.
func headerReasonFromOrigin(origin string) string {
	if strings.HasPrefix(origin, lapi.OriginPluginRulesPrefix) {
		return headerReasonRules
	}
	if strings.HasPrefix(origin, lapi.OriginPluginRateLimitPrefix) {
		return headerReasonRateLimit
	}
	switch origin {
	case lapi.OriginPluginLapiFailure:
		return headerReasonLAPIFailure
	case lapi.OriginPluginTechStreamFail:
		return headerReasonStreamUnhealthy
	case lapi.OriginPluginTechCacheFail:
		return headerReasonCacheFail
	case lapi.OriginPluginAppsecFailure:
		return headerReasonAppsecFailure
	case lapi.OriginPluginRateLimitChallengeForm:
		return headerReasonRateLimit
	case lapi.OriginPluginRateLimitFailure:
		return headerReasonRateLimitFailure
	case lapi.OriginPluginModsecFailure:
		return headerReasonModsecFailure
	default:
		return headerReasonLAPI
	}
}

// formatAppsecRelayHeader is the structured header for a relayed AppSec envelope (challenge, or an unknown action with a body).
func formatAppsecRelayHeader(action string) string {
	switch action {
	case appsec.ActionChallenge:
		return formatRemediationHeader(headerKindCaptcha, headerReasonChallenge, "")
	default:
		return formatRemediationHeader(sanitizeAppsecAction(action), headerReasonAppsec, "")
	}
}

// sanitizeAppsecAction keeps an unknown AppSec action as one kind field.
func sanitizeAppsecAction(action string) string {
	action = strings.TrimSpace(action)
	action = stripHeaderCtl(action)
	return strings.ReplaceAll(action, ":", "_")
}

// stripHeaderCtl removes CR, LF, and TAB so the value cannot split Traefik log lines.
func stripHeaderCtl(value string) string {
	return strings.NewReplacer("\r", "", "\n", "", "\t", "").Replace(value)
}

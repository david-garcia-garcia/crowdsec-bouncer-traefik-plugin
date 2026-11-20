// Package bouncer is the per-router Crowdsec handler Traefik gets back from New.
package bouncer

import (
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"text/template"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/appsec"
	captcha "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/captcha"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/clientrequest"
	configuration "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/httprule"
	ip "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/ip"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/lapi"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/modsecurity"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/ratelimit"
)

// Bouncer is one Traefik router handler. It is not the reclaim value.
type Bouncer struct {
	appsecBound              atomic.Value // *appsec.Client; typed nil when empty
	appsecFailureAction      string
	actionRules              *httprule.ActionSet
	banTemplate              *template.Template
	banTemplateContentType   string
	captchaBound             atomic.Value      // *captcha.Client; typed nil when empty
	modsecBound              atomic.Value      // *modsecurity.Client; typed nil when empty
	trustedClients           *ip.PoolStrategy  // client addresses that skip LAPI, AppSec, and ModSec
	decisionScopeHeaders     map[string]string // CrowdSec header scope → request header
	enabled                  bool
	forwardedCustomHeader    string
	forwardedHeadersInsecure bool
	lapiBound                atomic.Value // *lapi.Client; typed nil when empty
	lapiFailureAction        string       // per-router LAPI fallback (not on Client identity)
	lapiInstanceName         string
	appsecInstanceName       string
	captchaInstanceName      string
	modsecInstanceName       string
	modsecFailureAction      string
	subscribeLAPI            bool
	subscribeAppSec          bool
	subscribeCaptcha         bool
	subscribeModsec          bool
	redisUnreachableBlock    bool  // per-router Redis fail-closed
	defaultDecisionSeconds   int64 // per-router live-cache TTL passed into LiveLookup
	log                      *slog.Logger
	bindingMu                sync.Mutex
	lapiReceived             *lapi.Client
	appsecReceived           *appsec.Client
	captchaReceived          *captcha.Client
	modsecReceived           *modsecurity.Client
	lapiReceiveSeen          bool
	appsecReceiveSeen        bool
	captchaReceiveSeen       bool
	modsecReceiveSeen        bool
	name                     string
	next                     http.Handler
	rateLimitBuckets         *ratelimit.BucketSet // nil when rateLimitEnabled is false
	rateLimitCounter         ratelimit.Counter    // set once by AttachRateLimit before the handler is returned
	rateLimitFailureAction   string               // per-router answer when the counter errors
	rateLimitResponseHeaders bool
	rateLimitStatusCode      int
	remediationCustomHeader  string
	remediationStatusCode    int
	trustedHops              *ip.PoolStrategy // hops allowed to set the forwarded client header
	traceCustomHeader        string
	originBasedDecisionRemap map[string]map[string]string // per-router apply; LAPI/store keep original kinds
}

const msgBanTemplateUnavailable = "crowdsec bouncer ban template unavailable"

// New returns a per-router handler. Clients arrive later through ReceiveLAPI, ReceiveAppSec, ReceiveCaptcha, and ReceiveModSec.
func New(next http.Handler, name string, config *configuration.Config, subscribeLAPI, subscribeAppSec, subscribeCaptcha, subscribeModsec bool, log *slog.Logger) (*Bouncer, error) {
	log = log.With("traefikName", name)
	hopChecker, _ := ip.NewChecker(log, config.BouncerForwardedHeadersTrustedIPs)
	clientChecker, _ := ip.NewChecker(log, config.BouncerClientTrustedIPs)
	forwardedCustomHeader := config.BouncerForwardedHeadersCustomName
	if config.BouncerForwardedHeadersInsecure && forwardedCustomHeader == "X-Forwarded-For" {
		forwardedCustomHeader = "X-Real-Ip"
	}
	if config.BouncerForwardedHeadersInsecure {
		log.Info("BouncerForwardedHeadersInsecure enabled", "header", forwardedCustomHeader)
	}

	actionRules, err := httprule.NewActionSet(config.BouncerActionRules)
	if err != nil {
		return nil, err
	}
	// Buckets compile only when this router runs the rate limit; the counter arrives through AttachRateLimit.
	var rateLimitBuckets *ratelimit.BucketSet
	if config.RateLimitEnabled {
		rateLimitBuckets, err = ratelimit.NewBucketSet(config.RateLimitBuckets)
		if err != nil {
			return nil, err
		}
	}

	var banTemplate *template.Template
	var banTemplateContentType string
	if config.BouncerBanFilePath == "" {
		log.Warn(msgBanTemplateUnavailable, "reason", "empty")
	} else {
		var err error
		banTemplate, banTemplateContentType, err = configuration.GetTemplate(config.BouncerBanFilePath)
		if err != nil {
			log.Warn(msgBanTemplateUnavailable, "reason", configuration.TemplateUnavailableReason(config.BouncerBanFilePath, err))
			banTemplate = nil
			banTemplateContentType = ""
		}
	}

	routeHandler := &Bouncer{
		appsecFailureAction:      configuration.EffectiveFailureAction(config.BouncerAppsecFailureAction),
		actionRules:              actionRules,
		banTemplate:              banTemplate,
		banTemplateContentType:   banTemplateContentType,
		trustedClients:           &ip.PoolStrategy{Checker: clientChecker},
		decisionScopeHeaders:     decisionscope.NormalizeDecisionScopeHeaders(config.BouncerDecisionScopeHeaders),
		enabled:                  config.BouncerEnabled,
		forwardedCustomHeader:    forwardedCustomHeader,
		forwardedHeadersInsecure: config.BouncerForwardedHeadersInsecure,
		lapiFailureAction:        configuration.EffectiveFailureAction(config.BouncerLapiFailureAction),
		lapiInstanceName:         config.LapiInstanceName,
		appsecInstanceName:       config.AppsecInstanceName,
		captchaInstanceName:      config.CaptchaInstanceName,
		modsecInstanceName:       config.ModsecInstanceName,
		modsecFailureAction:      configuration.EffectiveModsecFailureAction(config.BouncerModsecFailureAction),
		subscribeLAPI:            subscribeLAPI,
		subscribeAppSec:          subscribeAppSec,
		subscribeCaptcha:         subscribeCaptcha,
		subscribeModsec:          subscribeModsec,
		redisUnreachableBlock:    config.BouncerRedisUnreachableBlock,
		defaultDecisionSeconds:   config.LapiDefaultDecisionSeconds,
		log:                      log,
		name:                     name,
		next:                     next,
		rateLimitBuckets:         rateLimitBuckets,
		rateLimitFailureAction:   configuration.EffectiveFailureAction(config.RateLimitFailureAction),
		rateLimitResponseHeaders: config.RateLimitResponseHeaders,
		rateLimitStatusCode:      config.RateLimitStatusCode,
		remediationCustomHeader:  config.BouncerRemediationHeadersCustomName,
		remediationStatusCode:    config.BouncerRemediationStatusCode,
		trustedHops:              &ip.PoolStrategy{Checker: hopChecker},
		traceCustomHeader:        config.BouncerTraceHeadersCustomName,
		originBasedDecisionRemap: copyOriginBasedDecisionRemap(config.BouncerOriginBasedDecisionRemap),
	}
	// JSON slog prints a nil []string as null; empty lists stay lists.
	forwardedHeadersTrustedIPs := config.BouncerForwardedHeadersTrustedIPs
	if forwardedHeadersTrustedIPs == nil {
		forwardedHeadersTrustedIPs = []string{}
	}
	clientTrustedIPs := config.BouncerClientTrustedIPs
	if clientTrustedIPs == nil {
		clientTrustedIPs = []string{}
	}
	routeHandler.log.Debug("Bouncer initialized",
		"forwardedHeadersTrustedIPs", forwardedHeadersTrustedIPs,
		"clientTrustedIPs", clientTrustedIPs)
	return routeHandler, nil
}

// ServeHTTP is the per-router middleware handler.
//
// none: no stream, no cache; LiveLookup every request.
// live: no stream; LiveLookup, then memo in cache.
// stream: LAPI stream ticker writes the cache; request path only reads it.
// alone: same as stream, but the ticker is CAPI (no local CrowdSec).
// A router that did not subscribe to LAPI still runs AppSec.
func (b *Bouncer) ServeHTTP(rw http.ResponseWriter, httpReq *http.Request) {
	if !b.enabled {
		b.next.ServeHTTP(rw, httpReq)
		return
	}

	// prepare client request
	remoteIP, ipAddr, err := ip.GetRemoteIP(httpReq, b.trustedHops, b.forwardedCustomHeader, b.forwardedHeadersInsecure)
	if err != nil {
		b.log.Error("ServeHTTP:getRemoteIp", "remoteAddr", httpReq.RemoteAddr, "ip", remoteIP, "error", err)
		http.Error(rw, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
		return
	}
	req := clientrequest.New(httpReq, remoteIP, ipAddr)

	// Bypass trusted clients
	isTrusted := b.trustedClients.Checker.ContainsIP(req.IPAddr())
	logger.Trace(b.log, "ServeHTTP", "ip", req.IPAddrString(), "isTrusted", isTrusted)
	if isTrusted {
		b.next.ServeHTTP(rw, req.Request)
		// Trusted clients skip LAPI, the rate limit, AppSec, and ModSec.
		return
	}

	// If we have a lapi client, add this to metrics
	if lapiClient := b.loadedLAPI(); lapiClient != nil {
		lapiClient.IncProcessed(req.IPType())
	}

	// Return ASAP a ban that comes from an action rule
	match := b.foldActionRules(req)
	if match.BanName != "" {
		logger.Trace(b.log, "ServeHTTP", "ip", req.IPAddrString(), "actionRule", match.BanName)
		b.handleRemediationServeHTTP(rw, req, decisionscope.BannedValue, lapi.OriginPluginRules(match.BanName))
		return
	}

	if b.serveLAPI(rw, req, match) {
		return
	}
	if b.serveRateLimit(rw, req, match) {
		return
	}
	if b.serveAppSec(rw, req, match) {
		return
	}
	if b.serveModSec(rw, req, match) {
		return
	}
	b.next.ServeHTTP(rw, req.Request)
}

// AttachRateLimit gives this router the counter its rate-limit buckets are charged to. New calls it
// once, before it returns the handler, so ServeHTTP reads a plain field.
func (b *Bouncer) AttachRateLimit(counter ratelimit.Counter) {
	b.rateLimitCounter = counter
}

// foldActionRules reduces the action rules for req.
// The challenge prefix belongs to CrowdSec, not to the site: AppSec must answer it to solve the challenge,
// so a bypass or bypassAppsec rule that also matches it does not skip AppSec there. LAPI skips stay.
func (b *Bouncer) foldActionRules(req clientrequest.Request) httprule.ActionMatch {
	match := b.actionRules.Fold(req.Request)
	if match.AmbiguousPathName != "" {
		logger.Trace(b.log, "foldActionRules", "ip", req.IPAddrString(), "ambiguousPathRule", match.AmbiguousPathName)
	}
	if match.SkipAppsec && isCrowdsecChallengeCallbackPath(req.URL.Path) {
		logger.Trace(b.log, "foldActionRules", "ip", req.IPAddrString(), "challengePathKeepsAppsec", true)
		match.SkipAppsec = false
	}
	return match
}

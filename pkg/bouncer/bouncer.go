// Package bouncer is the per-router Crowdsec handler Traefik gets back from New.
package bouncer

import (
	"log/slog"
	"net/http"
	"sync"
	"text/template"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/clientrequest"
	configuration "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/httprule"
	ip "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/ip"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/lapi"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

// Bouncer is one Traefik router handler. It is not the reclaim value.
type Bouncer struct {
	appsecLeg                legBinding // *appsec.Client
	appsecFailureAction      string
	appsecBackOffAction      string // per-router answer while the shared AppSec gate backs off
	actionRules              *httprule.ActionSet
	banTemplate              *template.Template
	banTemplateContentType   string
	captchaLeg               legBinding        // *captcha.Client
	modsecLeg                legBinding        // *modsecurity.Client
	trustedClients           *ip.PoolStrategy  // client addresses that skip LAPI, AppSec, and ModSec
	decisionScopeHeaders     map[string]string // CrowdSec header scope → request header
	enabled                  bool
	forwardedCustomHeader    string
	forwardedHeadersInsecure bool
	lapiLeg                  legBinding // *lapi.Client
	lapiFailureAction        string     // per-router LAPI fallback (not on Client identity)
	lapiBackOffAction        string     // per-router answer while the shared live/none LAPI gate backs off
	modsecFailureAction      string
	modsecBackOffAction      string // per-router answer while the shared ModSec gate backs off
	redisUnreachableBlock    bool   // per-router Redis fail-closed
	defaultDecisionSeconds   int64  // per-router live-cache TTL passed into LiveLookup
	log                      *slog.Logger
	bindingMu                sync.Mutex // serializes bind / unbind traces of every leg
	name                     string
	next                     http.Handler
	rateLimitLeg             legBinding // *ratelimit.Client: the owner's counter, buckets, and policy
	remediationCustomHeader  string
	remediationStatusCode    int
	trustedHops              *ip.PoolStrategy // hops allowed to set the forwarded client header
	traceCustomHeader        string
	originBasedDecisionRemap map[string]map[string]string // per-router apply; LAPI/store keep original kinds
}

const msgBanTemplateUnavailable = "crowdsec bouncer ban template unavailable"

// Subscriptions says which published legs a route subscribes to. plugin.go sets a leg when
// bouncerEnabled is on and that leg's instance name is set.
type Subscriptions struct {
	LAPI      bool
	AppSec    bool
	Captcha   bool
	ModSec    bool
	RateLimit bool
}

// New returns a per-router handler. Clients arrive later through ReceiveLAPI, ReceiveAppSec, ReceiveCaptcha,
// ReceiveModSec, and ReceiveRateLimit.
func New(next http.Handler, name string, config *configuration.Config, subscriptions Subscriptions, log *slog.Logger) (*Bouncer, error) {
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
		// One binding per published leg; leg is the plugin's reclaim group name.
		lapiLeg:                  legBinding{leg: "lapi", instanceName: config.LapiInstanceName, subscribed: subscriptions.LAPI},
		appsecLeg:                legBinding{leg: "appsec", instanceName: config.AppsecInstanceName, subscribed: subscriptions.AppSec},
		captchaLeg:               legBinding{leg: "captcha", instanceName: config.CaptchaInstanceName, subscribed: subscriptions.Captcha},
		modsecLeg:                legBinding{leg: "modsec", instanceName: config.ModsecInstanceName, subscribed: subscriptions.ModSec},
		rateLimitLeg:             legBinding{leg: "ratelimit", instanceName: config.RateLimitInstanceName, subscribed: subscriptions.RateLimit},
		appsecFailureAction:      configuration.EffectiveAppsecFailureAction(config.BouncerAppsecFailureAction),
		appsecBackOffAction:      configuration.EffectiveAppsecBackOffAction(config.BouncerAppsecBackOffAction),
		actionRules:              actionRules,
		banTemplate:              banTemplate,
		banTemplateContentType:   banTemplateContentType,
		trustedClients:           &ip.PoolStrategy{Checker: clientChecker},
		decisionScopeHeaders:     decisionscope.NormalizeDecisionScopeHeaders(config.BouncerDecisionScopeHeaders),
		enabled:                  config.BouncerEnabled,
		forwardedCustomHeader:    forwardedCustomHeader,
		forwardedHeadersInsecure: config.BouncerForwardedHeadersInsecure,
		lapiFailureAction:        configuration.EffectiveLapiFailureAction(config.BouncerLapiFailureAction),
		lapiBackOffAction:        configuration.EffectiveLapiBackOffAction(config.BouncerLapiBackOffAction),
		modsecFailureAction:      configuration.EffectiveModsecFailureAction(config.BouncerModsecFailureAction),
		modsecBackOffAction:      configuration.EffectiveModsecBackOffAction(config.BouncerModsecBackOffAction),
		redisUnreachableBlock:    config.BouncerRedisUnreachableBlock,
		defaultDecisionSeconds:   config.LapiDefaultDecisionSeconds,
		log:                      log,
		name:                     name,
		next:                     next,
		remediationCustomHeader:  config.BouncerRemediationHeadersCustomName,
		remediationStatusCode:    config.BouncerRemediationStatusCode,
		trustedHops:              &ip.PoolStrategy{Checker: hopChecker},
		traceCustomHeader:        config.BouncerTraceHeadersCustomName,
		originBasedDecisionRemap: copyOriginBasedDecisionRemap(config.BouncerOriginBasedDecisionRemap),
	}
	routeHandler.warnStricterBackOffActions(config, subscriptions)
	// A router rebuilt without the rate limit drops the owner-unavailable WARN its name still has pending.
	if !subscriptions.RateLimit {
		pendingRateLimitOwnerWarnings.forget(name)
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

// foldActionRules reduces the action rules for req.
// The challenge prefix belongs to CrowdSec, not to the site: AppSec must answer it to solve the challenge,
// so a bypass or bypassAppsec rule that also matches it does not skip AppSec there. LAPI skips stay.
func (b *Bouncer) foldActionRules(req clientrequest.Request) httprule.ActionMatch {
	match := b.actionRules.Fold(req)
	if match.AmbiguousPathName != "" {
		logger.Trace(b.log, "foldActionRules", "ip", req.IPAddrString(), "ambiguousPathRule", match.AmbiguousPathName)
	}
	if match.SkipAppsec && isCrowdsecChallengeCallbackPath(req.URL.Path) {
		logger.Trace(b.log, "foldActionRules", "ip", req.IPAddrString(), "challengePathKeepsAppsec", true)
		match.SkipAppsec = false
	}
	return match
}

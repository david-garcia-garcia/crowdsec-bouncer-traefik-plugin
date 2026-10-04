// Package bouncer is the per-router Crowdsec handler Traefik gets back from New.
package bouncer

import (
	"errors"
	"html"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"text/template"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/appsec"
	captcha "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/captcha"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/clientrequest"
	configuration "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionstore"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/httprule"
	ip "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/ip"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/lapi"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/reclaim"
)

// Bouncer is one Traefik router handler. It is not the reclaim value.
type Bouncer struct {
	appsecBound              atomic.Value // *appsec.Client; typed nil when empty
	appsecFailureAction      string
	actionRules              *httprule.ActionSet
	banTemplate              *template.Template
	banTemplateContentType   string
	captchaBound             atomic.Value      // *captcha.Client; typed nil when empty
	trustedClients           *ip.PoolStrategy  // client addresses that skip LAPI and AppSec
	decisionScopeHeaders     map[string]string // CrowdSec header scope → request header
	enabled                  bool
	forwardedCustomHeader    string
	forwardedHeadersInsecure bool
	lapiBound                atomic.Value // *lapi.Client; typed nil when empty
	lapiFailureAction        string       // per-router LAPI fallback (not on Client identity)
	lapiInstanceName         string
	appsecInstanceName       string
	captchaInstanceName      string
	subscribeLAPI            bool
	subscribeAppSec          bool
	subscribeCaptcha         bool
	startupBlock             bool
	redisUnreachableBlock    bool  // per-router Redis fail-closed
	defaultDecisionSeconds   int64 // per-router live-cache TTL passed into LiveLookup
	log                      *slog.Logger
	bindingMu                sync.Mutex
	lapiReceived             *lapi.Client
	appsecReceived           *appsec.Client
	captchaReceived          *captcha.Client
	lapiReceiveSeen          bool
	appsecReceiveSeen        bool
	captchaReceiveSeen       bool
	name                     string
	next                     http.Handler
	remediationCustomHeader  string
	remediationStatusCode    int
	trustedHops              *ip.PoolStrategy // hops allowed to set the forwarded client header
	traceCustomHeader        string
	originBasedDecisionRemap map[string]map[string]string // per-router apply; LAPI/store keep original kinds
}

const msgBackendMissing = "crowdsec bouncer backend missing"
const msgBanTemplateUnavailable = "crowdsec bouncer ban template unavailable"
const msgCaptchaUnsubscribed = "crowdsec bouncer captcha unsubscribed"

// New returns a per-router handler. Clients arrive later through ReceiveLAPI, ReceiveAppSec, and ReceiveCaptcha.
func New(next http.Handler, name string, config *configuration.Config, subscribeLAPI, subscribeAppSec, subscribeCaptcha bool, log *slog.Logger) (*Bouncer, error) {
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
		subscribeLAPI:            subscribeLAPI,
		subscribeAppSec:          subscribeAppSec,
		subscribeCaptcha:         subscribeCaptcha,
		startupBlock:             config.BouncerStartupBlock,
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

// storeBinding publishes value as a new immutable *reclaim.Box.
// Never assign Box.Value in place: concurrent Unbox reads that field without sync.
func (b *Bouncer) storeBinding(dest *atomic.Value, value any) {
	dest.Store(&reclaim.Box{Value: value})
}

// traceBouncerBinding records whether this route bound or released the named backend.
// An empty incarnation is omitted, which is the case where nothing was bound before.
func (b *Bouncer) traceBouncerBinding(bound bool, leg, instanceName, incarnation string) {
	msg := "crowdsec bouncer unbound"
	if bound {
		msg = "crowdsec bouncer bound"
	}
	attrs := []any{
		"traefikName", b.name,
		"leg", leg,
		"instanceName", instanceName,
	}
	if incarnation != "" {
		attrs = append(attrs, "incarnation", incarnation)
	}
	logger.Trace(b.log, msg, attrs...)
}

// warnCaptchaSuperseded logs when a captcha rule lost to a ban from another leg.
func (b *Bouncer) warnCaptchaSuperseded(req clientrequest.Request, match httprule.ActionMatch) {
	if match.CaptchaName == "" {
		return
	}
	b.log.Warn("ServeHTTP:forcedCaptchaSuperseded", "ip", req.RemoteIP(), "name", match.CaptchaName)
}

// passOrCaptchaRule passes to next, or applies a captcha rule after remaining legs.
func (b *Bouncer) passOrCaptchaRule(rw http.ResponseWriter, req clientrequest.Request) {
	match := b.actionRules.Fold(req.Request)
	if match.CaptchaName != "" {
		b.applyCaptchaRuleServeHTTP(rw, req, match)
		return
	}
	b.appsecThenNextServeHTTP(rw, req)
}

// applyCaptchaRuleServeHTTP queries AppSec unless skipped, then serves the plugin captcha gate.
func (b *Bouncer) applyCaptchaRuleServeHTTP(rw http.ResponseWriter, req clientrequest.Request, match httprule.ActionMatch) {
	if !match.SkipAppsec && b.subscribeAppSec && b.applyAppsecServeHTTP(rw, req) {
		return
	}
	b.handleRemediationServeHTTP(rw, req, decisionscope.CaptchaValue, lapi.OriginPluginRules(match.CaptchaName))
}

// remediateOrCaptchaRule applies lookup kind. A captcha rule does not replace CrowdSec captcha.
func (b *Bouncer) remediateOrCaptchaRule(rw http.ResponseWriter, req clientrequest.Request, kind, origin string) {
	match := b.actionRules.Fold(req.Request)
	if decisionscope.RemediationKind(kind) == decisionscope.BannedValue {
		b.warnCaptchaSuperseded(req, match)
	}
	b.handleRemediationServeHTTP(rw, req, kind, origin)
}

// banOrWarnCaptchaRule bans, and WARNs when a captcha rule lost.
func (b *Bouncer) banOrWarnCaptchaRule(rw http.ResponseWriter, req clientrequest.Request, reason, headerReason, origin string) {
	b.warnCaptchaSuperseded(req, b.actionRules.Fold(req.Request))
	b.handleBanServeHTTP(rw, req, reason, headerReason, origin)
}

// ServeHTTP is the per-router middleware handler.
//
// none: no stream, no cache; LiveLookup every request.
// live: no stream; LiveLookup, then memo in cache.
// stream: LAPI stream ticker writes the cache; request path only reads it.
// alone: same as stream, but the ticker is CAPI (no local CrowdSec).
// appsec: no LAPI; skip to the pass path (AppSec if enabled).
//
// ServeHTTP is a mode dispatcher; gocyclo/funlen fire on the flattened branches.
//
//nolint:gocyclo,gocognit,funlen
func (b *Bouncer) ServeHTTP(rw http.ResponseWriter, httpReq *http.Request) {
	if !b.enabled {
		b.next.ServeHTTP(rw, httpReq)
		return
	}

	if b.startupBlock {
		if b.subscribeLAPI && b.loadedLAPI() == nil {
			b.log.Warn(msgBackendMissing, "leg", "lapi", "instanceName", b.lapiInstanceName)
			rw.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if b.subscribeAppSec && b.loadedAppSec() == nil {
			b.log.Warn(msgBackendMissing, "leg", "appsec", "instanceName", b.appsecInstanceName)
			rw.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if b.subscribeCaptcha && b.loadedCaptcha() == nil {
			b.log.Warn(msgBackendMissing, "leg", "captcha", "instanceName", b.captchaInstanceName)
			rw.WriteHeader(http.StatusServiceUnavailable)
			return
		}
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
	logger.Trace(b.log, "ServeHTTP", "ip", req.RemoteIP(), "isTrusted", isTrusted)
	if isTrusted {
		b.next.ServeHTTP(rw, req.Request)
		// Trusted clients skip LAPI and AppSec.
		return
	}

	// Lapi MODE is very coupled with the bouncer logic
	lapiClient := b.loadedLAPI()
	crowdsecMode := ""
	if lapiClient != nil {
		crowdsecMode = lapiClient.Mode()
	}

	// If we have a lapi client, add this to metrics
	if lapiClient != nil {
		lapiClient.IncProcessed(req.IPType())
	}

	match := b.actionRules.Fold(req.Request)
	if match.BanName != "" {
		logger.Trace(b.log, "ServeHTTP", "ip", req.RemoteIP(), "actionRule", match.BanName)
		b.handleRemediationServeHTTP(rw, req, decisionscope.BannedValue, lapi.OriginPluginRules(match.BanName))
		return
	}
	if match.SkipLapi {
		b.passOrCaptchaRule(rw, req)
		return
	}

	if b.subscribeLAPI && lapiClient == nil {
		b.applyLapiFailureAction(rw, req, configuration.ReasonLAPI, lapi.OriginPluginLapiFailure)
		return
	}
	if !b.subscribeLAPI {
		b.passOrCaptchaRule(rw, req)
		return
	}

	// Mapped scope headers for this request. Missing headers are omitted.
	scopes := decisionscope.RequestScopeValues(b.decisionScopeHeaders, req.Request)

	// live, stream, and alone consult the cache.
	if crowdsecMode == configuration.LiveMode || crowdsecMode == configuration.StreamMode || crowdsecMode == configuration.AloneMode {
		var kind, origin string
		var originID uint16
		var lookupErr error
		kind, origin, originID, lookupErr = lapiClient.LookupRemediation(req.RemoteIP(), req.IPAddr(), scopes)
		if lookupErr != nil {
			b.log.Debug("ServeHTTP:Get", "ip", req.RemoteIP(), "cache", lookupErr)
			if errors.Is(lookupErr, decisionstore.ErrUnreachable) && !b.redisUnreachableBlock {
				b.log.Error("ServeHTTP:Get", "ip", req.RemoteIP(), "redisUnreachable", true)
				b.passOrCaptchaRule(rw, req)
				return
			}
			b.log.Error("ServeHTTP:Get", "ip", req.RemoteIP(), "error", lookupErr)
			b.banOrWarnCaptchaRule(rw, req, configuration.ReasonTECH, headerReasonCacheFail, lapi.OriginPluginTechCacheFail)
			return
		}
		kind, origin = b.appliedLAPIRemediation(kind, origin, originID)
		switch {
		case decisionscope.IsActiveRemediation(kind):
			logger.Trace(b.log, "ServeHTTP", appendScopesGroup([]any{"ip", req.RemoteIP(), "remediation", kind}, scopes)...)
			b.remediateOrCaptchaRule(rw, req, kind, b.resolveDroppedOrigin(origin, originID))
			return
		case kind == decisionscope.NoBannedValue:
			b.passOrCaptchaRule(rw, req)
			return
		}
	}

	if crowdsecMode == configuration.StreamMode || crowdsecMode == configuration.AloneMode {
		if lapiClient.StreamHealthy() {
			b.passOrCaptchaRule(rw, req)
			// No decision affecting this IP.
			return
		}
		b.log.Debug("ServeHTTP", "isCrowdsecStreamHealthy", false, "ip", req.RemoteIP())
		b.applyLapiFailureAction(rw, req, configuration.ReasonTECH, lapi.OriginPluginTechStreamFail)
		// Stream/alone never query LAPI per request. Miss is allow or failure action.
		return
	}

	if crowdsecMode == configuration.LiveMode || crowdsecMode == configuration.NoneMode {
		kind, origin, err := lapiClient.LiveLookup(req.RemoteIP(), scopes, b.defaultDecisionSeconds)
		if err != nil {
			b.log.Debug("ServeHTTP:LiveLookup", "error", err.Error())
			if !decisionscope.IsActiveRemediation(kind) {
				b.applyLapiFailureAction(rw, req, configuration.ReasonLAPI, lapi.OriginPluginLapiFailure)
				return
			}
		}
		kind, origin = b.appliedLAPIRemediation(kind, origin, 0)
		if kind == decisionscope.NoBannedValue {
			b.passOrCaptchaRule(rw, req)
			return
		}
		logger.Trace(b.log, "ServeHTTP:LiveLookup", appendScopesGroup([]any{"ip", req.RemoteIP(), "isBanned", kind}, scopes)...)
		b.remediateOrCaptchaRule(rw, req, kind, origin)
	}
}

// applyLapiFailureAction remediates a live LAPI error or stream-unhealthy cache miss.
func (b *Bouncer) applyLapiFailureAction(rw http.ResponseWriter, req clientrequest.Request, banReason, origin string) {
	switch b.lapiFailureAction {
	case configuration.FailureActionPassthrough:
		b.passOrCaptchaRule(rw, req)
	case configuration.FailureActionCaptcha:
		b.remediateOrCaptchaRule(rw, req, decisionscope.CaptchaValue, origin)
	default:
		b.banOrWarnCaptchaRule(rw, req, banReason, headerReasonFromOrigin(origin), origin)
	}
}

// recordProcessed counts this request on the connection usage-metrics window.
// recordDropped counts a remediating response on the connection usage-metrics window (request and byte series).
func (b *Bouncer) recordDropped(req clientrequest.Request, origin, remediation string) {
	if client := b.loadedLAPI(); client != nil {
		client.IncDropped(origin, req.IPType(), remediation)
		client.IncDroppedBytes(origin, req.IPType(), req.EstimatedSize())
	}
}

// handleBanServeHTTP writes the operator ban template for this client.
func (b *Bouncer) handleBanServeHTTP(rw http.ResponseWriter, req clientrequest.Request, reason, headerReason, origin string) {
	b.recordDropped(req, origin, "ban")

	if b.remediationCustomHeader != "" {
		if value := formatRemediationHeader(headerKindBan, headerReason, origin); value != "" {
			rw.Header().Set(b.remediationCustomHeader, value)
		}
	}
	rw.Header().Set("Content-Type", b.banTemplateContentType)
	rw.Header().Set("Cache-Control", "no-cache, no-store")
	rw.WriteHeader(b.remediationStatusCode)
	if b.banTemplate == nil || req.Method == http.MethodHead {
		return
	}
	templateData := map[string]string{
		"RemediationReason": reason,
		"ClientIP":          req.RemoteIP(),
		"Domain":            html.EscapeString(captcha.RequestDomain(req.Host)),
	}

	if b.traceCustomHeader != "" {
		headerValue := req.Header.Get(b.traceCustomHeader)
		templateData["TraceID"] = trustedTraceID(headerValue)
	}

	err := b.banTemplate.Execute(rw, templateData)
	if err != nil {
		b.log.Warn("handleBanServeHTTP could not write template to ResponseWriter", "error", err)
	}
}

// handleClientDisconnectedServeHTTP stops the request without a ban when the client dropped the body.
func (b *Bouncer) handleClientDisconnectedServeHTTP(rw http.ResponseWriter, req clientrequest.Request) {
	logger.Trace(b.log, "client disconnected while buffering AppSec body", "ip", req.RemoteIP())
	if b.remediationCustomHeader != "" {
		if value := formatRemediationHeader(headerKindError, headerReasonClientDisconnected, ""); value != "" {
			rw.Header().Set(b.remediationCustomHeader, value)
		}
	}
}

// resolveDroppedOrigin uses a payload origin string, or OriginName(originID) on drop only.
func (b *Bouncer) resolveDroppedOrigin(origin string, originID uint16) string {
	if origin != "" {
		return origin
	}
	if originID == 0 {
		return ""
	}
	if client := b.loadedLAPI(); client != nil {
		return client.OriginName(originID)
	}
	return ""
}

// handleRemediationServeHTTP applies captcha or ban for a cached or live verdict.
//
// Captcha kind serves a challenge only when this router subscribed and the
// client is usable (every method, HEAD included). Unsubscribed captcha kind
// WARNs crowdsec bouncer captcha unsubscribed then handleBanServeHTTP.
func (b *Bouncer) handleRemediationServeHTTP(rw http.ResponseWriter, req clientrequest.Request, remediation, origin string) {
	kind := decisionscope.RemediationKind(remediation)
	logger.Trace(b.log, "handleRemediationServeHTTP", "ip", req.RemoteIP(), "remediation", kind)
	if kind == decisionscope.CaptchaValue {
		b.handleCaptchaKindServeHTTP(rw, req, origin)
		return
	}
	b.handleBanServeHTTP(rw, req, configuration.ReasonLAPI, headerReasonFromOrigin(origin), origin)
}

// handleCaptchaKindServeHTTP serves a challenge, or bans when this router cannot.
func (b *Bouncer) handleCaptchaKindServeHTTP(rw http.ResponseWriter, req clientrequest.Request, origin string) {
	if !b.subscribeCaptcha {
		b.log.Warn(msgCaptchaUnsubscribed, "leg", "captcha", "instanceName", b.captchaInstanceName)
		b.handleBanServeHTTP(rw, req, configuration.ReasonLAPI, headerReasonCaptchaDowngrade, origin)
		return
	}
	captchaClient := b.loadedCaptcha()
	if captchaClient == nil || !captchaClient.Valid {
		b.handleBanServeHTTP(rw, req, configuration.ReasonLAPI, headerReasonCaptchaDowngrade, origin)
		return
	}

	// Same-origin widget assets must load while the visitor is still unsolved.
	if captchaClient.IsCustomResourceRequest(req.Request) {
		b.appsecThenNextServeHTTP(rw, req)
		return
	}

	// A valid gate cookie plus a captcha-form POST is a second-tab submit, not origin traffic.
	if captchaClient.Check(req) {
		if captchaClient.IsCaptchaFormPost(req.Request) {
			captchaClient.WriteSolvedRedirect(rw, req.Request, b.remediationCustomHeader)
			return
		}
		b.appsecThenNextServeHTTP(rw, req)
		return
	}

	b.recordDropped(req, origin, "captcha")
	challengeValue := formatRemediationHeader(headerKindCaptcha, headerReasonFromOrigin(origin), origin)
	captchaClient.ServeHTTP(rw, req, b.remediationCustomHeader, challengeValue)
}

// appsecThenNextServeHTTP runs AppSec unless an action rule skips it, then calls next.
// An AppSec response returns before next.
func (b *Bouncer) appsecThenNextServeHTTP(rw http.ResponseWriter, req clientrequest.Request) {
	if b.actionRules.Fold(req.Request).SkipAppsec {
		b.next.ServeHTTP(rw, req.Request)
		return
	}
	if b.subscribeAppSec && b.applyAppsecServeHTTP(rw, req) {
		return
	}
	b.next.ServeHTTP(rw, req.Request)
}

// applyAppsecServeHTTP queries AppSec and writes a remediation when the request must not reach origin.
func (b *Bouncer) applyAppsecServeHTTP(rw http.ResponseWriter, req clientrequest.Request) bool {
	match := b.actionRules.Fold(req.Request)
	appsecClient := b.loadedAppSec()
	if appsecClient == nil {
		switch b.appsecFailureAction {
		case configuration.FailureActionPassthrough:
			return false
		case configuration.FailureActionCaptcha:
			b.handleRemediationServeHTTP(rw, req, decisionscope.CaptchaValue, lapi.OriginPluginAppsecFailure)
			return true
		default:
			b.warnCaptchaSuperseded(req, match)
			b.handleBanServeHTTP(rw, req, configuration.ReasonAPPSEC, headerReasonAppsecFailure, lapi.OriginPluginAppsecFailure)
			return true
		}
	}
	pol := appsec.Policy{
		FailureAction: b.appsecFailureAction,
	}
	decision, err := appsecClient.Query(req, pol)
	if errors.Is(err, appsec.ErrClientDisconnected) {
		b.handleClientDisconnectedServeHTTP(rw, req)
		return true
	}
	if errors.Is(err, appsec.ErrFailureCaptcha) {
		b.handleRemediationServeHTTP(rw, req, decisionscope.CaptchaValue, lapi.OriginPluginAppsecFailure)
		return true
	}
	if err != nil {
		b.log.Debug("applyAppsecServeHTTP", "ip", req.RemoteIP(), "isWaf", true, "error", err)
		b.warnCaptchaSuperseded(req, match)
		b.handleBanServeHTTP(rw, req, configuration.ReasonAPPSEC, headerReasonAppsecFailure, lapi.OriginPluginAppsecFailure)
		return true
	}
	if decision == nil || decision.Action == "" || decision.Action == appsec.ActionAllow {
		return false
	}
	switch decision.Action {
	case appsec.ActionBan:
		b.warnCaptchaSuperseded(req, match)
		b.handleBanServeHTTP(rw, req, configuration.ReasonAPPSEC, headerReasonAppsec, "appsec")
		return true
	case appsec.ActionChallenge:
		if decision.UserBodyContent == "" {
			b.warnCaptchaSuperseded(req, match)
			b.handleBanServeHTTP(rw, req, configuration.ReasonAPPSEC, headerReasonAppsecChallengeEmpty, "appsec")
			return true
		}
		if match.CaptchaName != "" {
			return false
		}
	}
	b.handleAppsecResponseServeHTTP(rw, req, decision)
	return true
}

// handleAppsecResponseServeHTTP writes a structured AppSec envelope (challenge HTML, cookies, headers) to the client.
func (b *Bouncer) handleAppsecResponseServeHTTP(rw http.ResponseWriter, req clientrequest.Request, decision *appsec.Response) {
	b.recordDropped(req, "appsec", "")

	// Copy AppSec-supplied headers, skipping hop-by-hop names and Set-Cookie (cookies have their own field).
	for name, values := range decision.UserHeaders {
		if isHopByHopHeader(name) || strings.EqualFold(name, "Set-Cookie") {
			continue
		}
		rw.Header()[http.CanonicalHeaderKey(name)] = values
	}
	for _, cookie := range decision.UserCookies {
		rw.Header().Add("Set-Cookie", cookie)
	}
	if b.remediationCustomHeader != "" {
		if value := formatAppsecRelayHeader(decision.Action); value != "" {
			rw.Header().Set(b.remediationCustomHeader, value)
		}
	}
	if rw.Header().Get("Content-Type") == "" && b.banTemplateContentType != "" {
		rw.Header().Set("Content-Type", b.banTemplateContentType)
	}

	status := decision.HTTPStatus
	if status == 0 {
		status = http.StatusOK
	}
	if status < 100 || status > 999 {
		status = b.remediationStatusCode
	}

	rw.WriteHeader(status)

	if req.Method == http.MethodHead || decision.UserBodyContent == "" {
		return
	}
	if _, err := rw.Write([]byte(decision.UserBodyContent)); err != nil {
		b.log.Warn("handleAppsecResponseServeHTTP could not write appsec response", "ip", req.RemoteIP(), "error", err)
	}
}

// isHopByHopHeader reports names that must not be copied from AppSec onto the client response.
func isHopByHopHeader(name string) bool {
	switch http.CanonicalHeaderKey(name) {
	case "Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Te", "Trailers", "Transfer-Encoding", "Upgrade":
		return true
	default:
		return false
	}
}

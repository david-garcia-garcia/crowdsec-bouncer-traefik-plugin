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

// warnCaptchaSuperseded logs when a captcha rule lost to a ban from another leg.
func (b *Bouncer) warnCaptchaSuperseded(req clientrequest.Request, match httprule.ActionMatch) {
	if match.CaptchaName == "" {
		return
	}
	b.log.Warn("warnCaptchaSuperseded", "ip", req.IPAddrString(), "name", match.CaptchaName)
}

// applyCaptchaRuleServeHTTP queries AppSec unless this rule skips it.
// When AppSec does not write the response, it serves this router's captcha gate.
func (b *Bouncer) applyCaptchaRuleServeHTTP(rw http.ResponseWriter, req clientrequest.Request, match httprule.ActionMatch) {
	if !match.SkipAppsec && b.subscribeAppSec && b.applyAppsecServeHTTP(rw, req, match) {
		return
	}
	b.handleRemediationServeHTTP(rw, req, decisionscope.CaptchaValue, lapi.OriginPluginRules(match.CaptchaName))
}

// remediateWarnCaptchaRuleOnBan writes kind and origin.
// When kind is a ban and a captcha action rule also matched, it warns that the rule lost.
func (b *Bouncer) remediateWarnCaptchaRuleOnBan(rw http.ResponseWriter, req clientrequest.Request, match httprule.ActionMatch, kind, origin string) {
	if decisionscope.RemediationKind(kind) == decisionscope.BannedValue {
		b.warnCaptchaSuperseded(req, match)
	}
	b.handleRemediationServeHTTP(rw, req, kind, origin)
}

// banWarnCaptchaRule writes a ban. When a captcha action rule also matched, it warns that the rule lost.
func (b *Bouncer) banWarnCaptchaRule(rw http.ResponseWriter, req clientrequest.Request, match httprule.ActionMatch, reason, headerReason, origin string) {
	b.warnCaptchaSuperseded(req, match)
	b.handleBanServeHTTP(rw, req, reason, headerReason, origin)
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
		// Trusted clients skip LAPI and AppSec.
		return
	}

	// If we have a lapi client, add this to metrics
	if lapiClient := b.loadedLAPI(); lapiClient != nil {
		lapiClient.IncProcessed(req.IPType())
	}

	// Return ASAP a ban that comes from an action rule
	match := b.actionRules.Fold(req.Request)
	if match.BanName != "" {
		logger.Trace(b.log, "ServeHTTP", "ip", req.IPAddrString(), "actionRule", match.BanName)
		b.handleRemediationServeHTTP(rw, req, decisionscope.BannedValue, lapi.OriginPluginRules(match.BanName))
		return
	}

	if b.serveLAPI(rw, req, match) {
		return
	}
	if b.serveAppSec(rw, req, match) {
		return
	}
	b.next.ServeHTTP(rw, req.Request)
}

// serveLAPI reports whether LAPI wrote the response.
// False means LAPI had nothing to say, and ServeHTTP continues with AppSec.
func (b *Bouncer) serveLAPI(rw http.ResponseWriter, req clientrequest.Request, match httprule.ActionMatch) bool {
	if match.SkipLapi || !b.subscribeLAPI {
		return false
	}
	lapiClient := b.loadedLAPI()
	if lapiClient == nil {
		return b.applyLapiFailureAction(rw, req, match, configuration.ReasonLAPI, lapi.OriginPluginLapiFailure)
	}
	crowdsecMode := lapiClient.Mode()

	// Mapped scope headers for this request. Missing headers are omitted.
	scopes := decisionscope.RequestScopeValues(b.decisionScopeHeaders, req.Request)

	// live, stream, and alone consult the cache.
	if crowdsecMode == configuration.LiveMode || crowdsecMode == configuration.StreamMode || crowdsecMode == configuration.AloneMode {
		kind, origin, originID, lookupErr := lapiClient.LookupRemediation(req.IPAddrString(), req.IPAddr(), scopes)
		if lookupErr != nil {
			if errors.Is(lookupErr, decisionstore.ErrUnreachable) && !b.redisUnreachableBlock {
				b.log.Error("serveLAPI:Get", "ip", req.IPAddrString(), "redisUnreachable", true)
				return false
			}
			b.log.Error("serveLAPI:Get", "ip", req.IPAddrString(), "error", lookupErr)
			b.banWarnCaptchaRule(rw, req, match, configuration.ReasonTECH, headerReasonCacheFail, lapi.OriginPluginTechCacheFail)
			return true
		}
		kind, origin = b.appliedLAPIRemediation(kind, origin, originID)
		switch {
		case decisionscope.IsActiveRemediation(kind):
			logger.Trace(b.log, "serveLAPI", appendScopesGroup([]any{"ip", req.IPAddrString(), "remediation", kind}, scopes)...)
			b.remediateWarnCaptchaRuleOnBan(rw, req, match, kind, b.resolveDroppedOrigin(origin, originID))
			return true
		case kind == decisionscope.NoBannedValue:
			return false
		}
	}

	if crowdsecMode == configuration.StreamMode || crowdsecMode == configuration.AloneMode {
		if lapiClient.StreamHealthy() {
			// No decision affecting this IP.
			return false
		}
		logger.Trace(b.log, "serveLAPI", "isCrowdsecStreamHealthy", false, "ip", req.IPAddrString())
		// Stream/alone never query LAPI per request. Miss is allow or failure action.
		return b.applyLapiFailureAction(rw, req, match, configuration.ReasonTECH, lapi.OriginPluginTechStreamFail)
	}

	if crowdsecMode == configuration.LiveMode || crowdsecMode == configuration.NoneMode {
		kind, origin, lookupErr := lapiClient.LiveLookup(req.IPAddrString(), scopes, b.defaultDecisionSeconds)
		if lookupErr != nil {
			b.log.Debug("serveLAPI:LiveLookup", "error", lookupErr.Error())
			if !decisionscope.IsActiveRemediation(kind) {
				return b.applyLapiFailureAction(rw, req, match, configuration.ReasonLAPI, lapi.OriginPluginLapiFailure)
			}
		}
		kind, origin = b.appliedLAPIRemediation(kind, origin, 0)
		if kind == decisionscope.NoBannedValue {
			return false
		}
		logger.Trace(b.log, "serveLAPI:LiveLookup", appendScopesGroup([]any{"ip", req.IPAddrString(), "isBanned", kind}, scopes)...)
		b.remediateWarnCaptchaRuleOnBan(rw, req, match, kind, origin)
		return true
	}
	return true
}

// serveAppSec reports whether AppSec or a captcha rule wrote the response.
// A captcha rule is finished inside applyCaptchaRuleServeHTTP. False means ServeHTTP calls next.
func (b *Bouncer) serveAppSec(rw http.ResponseWriter, req clientrequest.Request, match httprule.ActionMatch) bool {
	if match.CaptchaName != "" {
		b.applyCaptchaRuleServeHTTP(rw, req, match)
		return true
	}
	if match.SkipAppsec {
		return false
	}
	return b.subscribeAppSec && b.applyAppsecServeHTTP(rw, req, match)
}

// applyLapiFailureAction applies this router's LAPI failure action.
// Callers are a missing subscribed client, a live lookup error, and an unhealthy stream miss.
// False is passthrough: the response is not written, and ServeHTTP continues with AppSec.
func (b *Bouncer) applyLapiFailureAction(rw http.ResponseWriter, req clientrequest.Request, match httprule.ActionMatch, banReason, origin string) bool {
	switch b.lapiFailureAction {
	case configuration.FailureActionPassthrough:
		return false
	case configuration.FailureActionCaptcha:
		b.remediateWarnCaptchaRuleOnBan(rw, req, match, decisionscope.CaptchaValue, origin)
		return true
	default:
		b.banWarnCaptchaRule(rw, req, match, banReason, headerReasonFromOrigin(origin), origin)
		return true
	}
}

// recordDropped counts a remediating response on the connection usage-metrics window, both the request and the byte series.
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
		"ClientIP":          req.IPAddrString(),
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

// handleClientDisconnectedServeHTTP sets the client-disconnected remediation header.
// It does not ban and does not call next. The caller returns so ServeHTTP stops.
func (b *Bouncer) handleClientDisconnectedServeHTTP(rw http.ResponseWriter, req clientrequest.Request) {
	logger.Trace(b.log, "client disconnected while buffering AppSec body", "ip", req.IPAddrString())
	if b.remediationCustomHeader != "" {
		if value := formatRemediationHeader(headerKindError, headerReasonClientDisconnected, ""); value != "" {
			rw.Header().Set(b.remediationCustomHeader, value)
		}
	}
}

// resolveDroppedOrigin returns origin when it is set.
// Otherwise it asks the published LAPI client for the name of originID.
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

// handleRemediationServeHTTP writes captcha or ban for kind.
// Callers include a lookup hit, a live lookup, a failure action, and an action-rule captcha.
//
// Captcha kind serves a challenge only when this router subscribed and the
// client is usable (every method, HEAD included). Unsubscribed captcha kind
// WARNs crowdsec bouncer captcha unsubscribed then handleBanServeHTTP.
func (b *Bouncer) handleRemediationServeHTTP(rw http.ResponseWriter, req clientrequest.Request, remediation, origin string) {
	kind := decisionscope.RemediationKind(remediation)
	logger.Trace(b.log, "handleRemediationServeHTTP", "ip", req.IPAddrString(), "remediation", kind)
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
	match := b.actionRules.Fold(req.Request)
	if match.SkipAppsec {
		b.next.ServeHTTP(rw, req.Request)
		return
	}
	if b.subscribeAppSec && b.applyAppsecServeHTTP(rw, req, match) {
		return
	}
	b.next.ServeHTTP(rw, req.Request)
}

// applyAppsecServeHTTP runs this router's AppSec check.
// True means the response was written. A missing client uses the AppSec failure action.
// A query that must not continue writes that remediation. False means the caller may continue.
func (b *Bouncer) applyAppsecServeHTTP(rw http.ResponseWriter, req clientrequest.Request, match httprule.ActionMatch) bool {
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
		b.log.Debug("applyAppsecServeHTTP", "ip", req.IPAddrString(), "isWaf", true, "error", err)
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
		b.log.Warn("handleAppsecResponseServeHTTP could not write appsec response", "ip", req.IPAddrString(), "error", err)
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

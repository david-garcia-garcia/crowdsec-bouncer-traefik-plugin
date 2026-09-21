// Package bouncer is the per-router Crowdsec handler Traefik gets back from New.
package bouncer

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"text/template"
	"time"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/appsec"
	captcha "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/captcha"
	configuration "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionstore"
	ip "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/ip"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/lapi"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

// Bouncer is one Traefik router handler. It is not the reclaim value.
type Bouncer struct {
	appsecClient             *appsec.Client
	appsecEnabled            bool
	appsecFailureAction      string
	banTemplate              *template.Template
	banTemplateContentType   string
	captchaClient            *captcha.Client
	clientPoolStrategy       *ip.PoolStrategy
	crowdsecMode             string
	decisionScopeHeaders     map[string]string // CrowdSec header scope → request header
	forcedDecisionHeader     string            // crowdsecDecisionHeader; empty = off
	enabled                  bool
	forwardedCustomHeader    string
	forwardedHeadersInsecure bool
	lapiClient               *lapi.Client
	lapiFailureAction        string // per-router LAPI fallback (not on Client identity)
	redisUnreachableBlock    bool   // per-router Redis fail-closed
	defaultDecisionSeconds   int64  // per-router live-cache TTL passed into LiveLookup
	log                      *slog.Logger
	name                     string
	next                     http.Handler
	remediationCustomHeader  string
	remediationStatusCode    int
	serverPoolStrategy       *ip.PoolStrategy
	template                 *template.Template
	traceCustomHeader        string
	originBasedDecisionRemap map[string]map[string]string // per-router apply; LAPI/store keep original kinds
}

// New returns a per-router handler bound to lapiClient and appsecClient.
func New(next http.Handler, name string, config *configuration.Config, lapiClient *lapi.Client, appsecClient *appsec.Client, log *slog.Logger) (http.Handler, error) {
	serverChecker, _ := ip.NewChecker(log, config.ForwardedHeadersTrustedIPs)
	clientChecker, _ := ip.NewChecker(log, config.ClientTrustedIPs)
	forwardedCustomHeader := config.ForwardedHeadersCustomName
	if config.ForwardedHeadersInsecure && forwardedCustomHeader == "X-Forwarded-For" {
		forwardedCustomHeader = "X-Real-Ip"
	}
	if config.ForwardedHeadersInsecure {
		log.Info("ForwardedHeadersInsecure enabled", "header", forwardedCustomHeader)
	}

	var banTemplate *template.Template
	var banTemplateContentType string
	if config.BanFilePath != "" {
		banTemplate, banTemplateContentType, _ = configuration.GetTemplate(config.BanFilePath)
	}

	routeHandler := &Bouncer{
		appsecClient:             appsecClient,
		appsecEnabled:            config.CrowdsecAppsecEnabled,
		appsecFailureAction:      configuration.EffectiveFailureAction(config.CrowdsecAppsecFailureAction),
		banTemplate:              banTemplate,
		banTemplateContentType:   banTemplateContentType,
		captchaClient:            &captcha.Client{},
		clientPoolStrategy:       &ip.PoolStrategy{Checker: clientChecker},
		crowdsecMode:             config.CrowdsecMode,
		decisionScopeHeaders:     decisionscope.NormalizeDecisionScopeHeaders(config.DecisionScopeHeaders),
		forcedDecisionHeader:     strings.TrimSpace(config.CrowdsecDecisionHeader),
		enabled:                  config.Enabled,
		forwardedCustomHeader:    forwardedCustomHeader,
		forwardedHeadersInsecure: config.ForwardedHeadersInsecure,
		lapiClient:               lapiClient,
		lapiFailureAction:        configuration.EffectiveFailureAction(config.CrowdsecLapiFailureAction),
		redisUnreachableBlock:    config.RedisCacheUnreachableBlock,
		defaultDecisionSeconds:   config.DefaultDecisionSeconds,
		log:                      log,
		name:                     name,
		next:                     next,
		remediationCustomHeader:  config.RemediationHeadersCustomName,
		remediationStatusCode:    config.RemediationStatusCode,
		serverPoolStrategy:       &ip.PoolStrategy{Checker: serverChecker},
		template:                 template.New("CrowdsecBouncer").Delims("[[", "]]"),
		traceCustomHeader:        config.TraceHeadersCustomName,
		originBasedDecisionRemap: copyOriginBasedDecisionRemap(config.OriginBasedDecisionRemap),
	}
	// Appsec mode has no LAPI decisions to remediate, but crowdsecAppsecFailureAction: captcha
	// still serves a challenge through this client (core_plugin_appsec_failure-action), and
	// handleRemediationServeHTTP bans whenever that client is not valid.
	if config.CrowdsecMode == configuration.AppsecMode &&
		routeHandler.appsecFailureAction != configuration.FailureActionCaptcha {
		routeHandler.log.Debug("Bouncer initialized", "name", name)
		return routeHandler, nil
	}
	config.CaptchaSiteKey, _ = configuration.GetVariable(config, "CaptchaSiteKey")
	config.CaptchaSecretKey, _ = configuration.GetVariable(config, "CaptchaSecretKey")
	captchaGateSecret, _ := configuration.GetVariable(config, "CaptchaGateSecret")
	err := routeHandler.captchaClient.New(
		log,
		&http.Client{
			Transport: &http.Transport{MaxIdleConns: 10, MaxIdleConnsPerHost: 10, IdleConnTimeout: 30 * time.Second},
			Timeout:   time.Duration(config.EffectiveHTTPTimeoutSeconds(config.CaptchaSiteverifyHTTPTimeoutSeconds)) * time.Second,
		},
		config.CaptchaProvider,
		config.CaptchaCustomJsURL,
		config.CaptchaCustomChallengeURL,
		config.CaptchaCustomKey,
		config.CaptchaCustomResponse,
		config.CaptchaCustomValidateURL,
		config.CaptchaCustomValidateBody,
		config.CaptchaSiteKey,
		config.CaptchaSecretKey,
		captchaGateSecret,
		config.CaptchaGateBindIP,
		config.RemediationHeadersCustomName,
		config.CaptchaFilePath,
		config.CaptchaGracePeriodSeconds,
	)
	if err != nil {
		log.Error("CaptchaClient not valid", "error", err)
		return nil, err
	}
	routeHandler.log.Debug("Bouncer initialized", "name", name)
	return routeHandler, nil
}

// LapiClient is the reclaimed LAPI backend this route uses.
func (b *Bouncer) LapiClient() *lapi.Client {
	return b.lapiClient
}

// SameLapiClient reports whether two routes share one LAPI client pointer.
func (b *Bouncer) SameLapiClient(other *Bouncer) bool {
	return other != nil && b.lapiClient == other.lapiClient
}

// forcedDecisionKind returns BannedValue or CaptchaValue when the configured
// request header forces ban or captcha, otherwise empty.
func (b *Bouncer) forcedDecisionKind(httpReq *http.Request) string {
	if b.forcedDecisionHeader == "" {
		return ""
	}
	switch strings.TrimSpace(httpReq.Header.Get(b.forcedDecisionHeader)) {
	case "b":
		return decisionscope.BannedValue
	case "c":
		return decisionscope.CaptchaValue
	default:
		return ""
	}
}

// passOrForcedCaptcha passes to next, or captcha when the header forced c.
func (b *Bouncer) passOrForcedCaptcha(rw http.ResponseWriter, req clientRequest) {
	if b.forcedDecisionKind(req.Request) == decisionscope.CaptchaValue {
		b.handleRemediationServeHTTP(rw, req, decisionscope.CaptchaValue, lapi.OriginPluginForcedDecision)
		return
	}
	b.handleNextServeHTTP(rw, req)
}

// remediateOrForcedCaptcha applies lookup kind. Header c yields captcha unless lookup is ban (then WARN).
func (b *Bouncer) remediateOrForcedCaptcha(rw http.ResponseWriter, req clientRequest, kind, origin string) {
	if b.forcedDecisionKind(req.Request) != decisionscope.CaptchaValue {
		b.handleRemediationServeHTTP(rw, req, kind, origin)
		return
	}
	if decisionscope.RemediationKind(kind) == decisionscope.BannedValue {
		b.log.Warn("ServeHTTP:forcedCaptchaSuperseded", "ip", req.remoteIP, "header", b.forcedDecisionHeader)
		b.handleRemediationServeHTTP(rw, req, kind, origin)
		return
	}
	b.handleRemediationServeHTTP(rw, req, decisionscope.CaptchaValue, lapi.OriginPluginForcedDecision)
}

// banOrWarnForcedCaptcha bans, and WARNs when the header asked for captcha.
func (b *Bouncer) banOrWarnForcedCaptcha(rw http.ResponseWriter, req clientRequest, reason, origin string) {
	if b.forcedDecisionKind(req.Request) == decisionscope.CaptchaValue {
		b.log.Warn("ServeHTTP:forcedCaptchaSuperseded", "ip", req.remoteIP, "header", b.forcedDecisionHeader)
	}
	b.handleBanServeHTTP(rw, req, reason, origin)
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
//nolint:gocyclo,funlen
func (b *Bouncer) ServeHTTP(rw http.ResponseWriter, httpReq *http.Request) {
	if !b.enabled {
		b.next.ServeHTTP(rw, httpReq)
		return
	}

	remoteIP, ipAddr, err := ip.GetRemoteIP(httpReq, b.serverPoolStrategy, b.forwardedCustomHeader, b.forwardedHeadersInsecure)
	req := clientRequest{
		Request:  httpReq,
		ipAddr:   ipAddr,
		ipType:   ip.FamilyOfIP(ipAddr),
		remoteIP: remoteIP,
	}
	b.recordProcessed(req.ipType)
	if err != nil {
		b.log.Error("ServeHTTP:getRemoteIp", "ip", req.remoteIP, "error", err)
		b.handleBanServeHTTP(rw, req, configuration.ReasonTECH, lapi.OriginPluginTechGetRemoteFail)
		return
	}
	if req.ipAddr == nil {
		b.log.Error("ServeHTTP:parseClientIP", "ip", req.remoteIP)
		b.handleBanServeHTTP(rw, req, configuration.ReasonTECH, lapi.OriginPluginTechTrustIPFail)
		return
	}
	// Lookup, live memo, and captcha bind share this spelling. GetRemoteIP still returned the raw text.
	req.remoteIP = req.ipAddr.String()
	isTrusted := b.clientPoolStrategy.Checker.ContainsIP(req.ipAddr)
	logger.Trace(b.log, "ServeHTTP", "ip", req.remoteIP, "isTrusted", isTrusted)
	if isTrusted {
		b.next.ServeHTTP(rw, req.Request)
		// Trusted clients skip LAPI and AppSec.
		return
	}

	// Header b remediates without lookup. Header c is merged after lookup so a ban still wins.
	if b.forcedDecisionKind(req.Request) == decisionscope.BannedValue {
		logger.Trace(b.log, "ServeHTTP", "ip", req.remoteIP, "forcedDecision", decisionscope.BannedValue)
		b.handleRemediationServeHTTP(rw, req, decisionscope.BannedValue, lapi.OriginPluginForcedDecision)
		return
	}

	if b.crowdsecMode == configuration.AppsecMode {
		b.passOrForcedCaptcha(rw, req)
		return
	}

	// Mapped scope headers for this request. Missing headers are omitted.
	scopes := decisionscope.RequestScopeValues(b.decisionScopeHeaders, req.Request)

	// live, stream, and alone consult the cache.
	if b.crowdsecMode == configuration.LiveMode || b.crowdsecMode == configuration.StreamMode || b.crowdsecMode == configuration.AloneMode {
		var kind, origin string
		var originID uint16
		var lookupErr error
		kind, origin, originID, lookupErr = b.lapiClient.LookupRemediation(req.remoteIP, req.ipAddr, scopes)
		switch {
		case lookupErr != nil:
			b.log.Debug("ServeHTTP:Get", "ip", req.remoteIP, "cache", lookupErr)
			if errors.Is(lookupErr, decisionstore.ErrUnreachable) && !b.redisUnreachableBlock {
				b.log.Error("ServeHTTP:Get", "ip", req.remoteIP, "redisUnreachable", true)
				b.passOrForcedCaptcha(rw, req)
				return
			}
			b.log.Error("ServeHTTP:Get", "ip", req.remoteIP, "error", lookupErr)
			b.banOrWarnForcedCaptcha(rw, req, configuration.ReasonTECH, lapi.OriginPluginTechCacheFail)
			return
		}
		kind, origin = b.appliedLAPIRemediation(kind, origin, originID)
		switch {
		case decisionscope.IsActiveRemediation(kind):
			logger.Trace(b.log, "ServeHTTP", "ip", req.remoteIP, "cache", "hit", "remediation", kind)
			b.remediateOrForcedCaptcha(rw, req, kind, b.resolveDroppedOrigin(origin, originID))
			return
		case kind == decisionscope.NoBannedValue:
			b.passOrForcedCaptcha(rw, req)
			return
		}
	}

	if b.crowdsecMode == configuration.StreamMode || b.crowdsecMode == configuration.AloneMode {
		if b.lapiClient.StreamHealthy() {
			b.passOrForcedCaptcha(rw, req)
			// No decision affecting this IP.
			return
		}
		b.log.Debug("ServeHTTP", "isCrowdsecStreamHealthy", false, "ip", req.remoteIP)
		b.applyLapiFailureAction(rw, req, configuration.ReasonTECH, lapi.OriginPluginTechStreamFail)
		// Stream/alone never query LAPI per request. Miss is allow or failure action.
		return
	}

	if b.crowdsecMode == configuration.LiveMode || b.crowdsecMode == configuration.NoneMode {
		kind, origin, err := b.lapiClient.LiveLookup(req.remoteIP, scopes, b.defaultDecisionSeconds)
		if err != nil {
			b.log.Debug("ServeHTTP:LiveLookup", "error", err.Error())
			if !decisionscope.IsActiveRemediation(kind) {
				b.applyLapiFailureAction(rw, req, configuration.ReasonLAPI, lapi.OriginPluginLapiFailure)
				return
			}
		}
		kind, origin = b.appliedLAPIRemediation(kind, origin, 0)
		if kind == decisionscope.NoBannedValue {
			b.passOrForcedCaptcha(rw, req)
			return
		}
		logger.Trace(b.log, "ServeHTTP:LiveLookup", "ip", req.remoteIP, "isBanned", kind)
		b.remediateOrForcedCaptcha(rw, req, kind, origin)
	}
}

// applyLapiFailureAction remediates a live LAPI error or stream-unhealthy cache miss.
func (b *Bouncer) applyLapiFailureAction(rw http.ResponseWriter, req clientRequest, banReason, origin string) {
	switch b.lapiFailureAction {
	case configuration.FailureActionPassthrough:
		b.passOrForcedCaptcha(rw, req)
	case configuration.FailureActionCaptcha:
		b.remediateOrForcedCaptcha(rw, req, decisionscope.CaptchaValue, origin)
	default:
		b.banOrWarnForcedCaptcha(rw, req, banReason, origin)
	}
}

// recordProcessed counts this request on the connection usage-metrics window.
func (b *Bouncer) recordProcessed(ipType string) {
	if b.lapiClient != nil {
		b.lapiClient.IncProcessed(ipType)
	}
}

// recordDropped counts a remediating response on the connection usage-metrics window.
func (b *Bouncer) recordDropped(origin, ipType, remediation string) {
	if b.lapiClient != nil {
		b.lapiClient.IncDropped(origin, ipType, remediation)
	}
}

// handleBanServeHTTP writes the operator ban template for this client.
func (b *Bouncer) handleBanServeHTTP(rw http.ResponseWriter, req clientRequest, reason, origin string) {
	b.recordDropped(origin, req.ipType, "ban")

	if b.remediationCustomHeader != "" {
		rw.Header().Set(b.remediationCustomHeader, "ban")
	}
	rw.Header().Set("Content-Type", b.banTemplateContentType)
	rw.WriteHeader(b.remediationStatusCode)
	if b.banTemplate == nil || req.Method == http.MethodHead {
		return
	}
	templateData := map[string]string{
		"RemediationReason": reason,
		"ClientIP":          req.remoteIP,
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

// resolveDroppedOrigin uses a payload origin string, or OriginName(originID) on drop only.
func (b *Bouncer) resolveDroppedOrigin(origin string, originID uint16) string {
	if origin != "" {
		return origin
	}
	if originID == 0 || b.lapiClient == nil {
		return ""
	}
	return b.lapiClient.OriginName(originID)
}

// handleRemediationServeHTTP applies captcha or ban for a cached or live verdict.
//
// Captcha routing covers every method, HEAD included: a HEAD from a client carrying a
// captcha remediation gets the captcha challenge page, never the ban page. Only ban kind
// reaches handleBanServeHTTP from here.
func (b *Bouncer) handleRemediationServeHTTP(rw http.ResponseWriter, req clientRequest, remediation, origin string) {
	kind := decisionscope.RemediationKind(remediation)
	logger.Trace(b.log, "handleRemediationServeHTTP", "ip", req.remoteIP, "remediation", kind)
	if !b.captchaClient.Valid || kind != decisionscope.CaptchaValue {
		b.handleBanServeHTTP(rw, req, configuration.ReasonLAPI, origin)
		return
	}

	// Same-origin widget assets must load while the visitor is still unsolved.
	if b.captchaClient.IsCustomResourceRequest(req.Request) {
		b.handleNextServeHTTP(rw, req)
		return
	}

	// A valid gate cookie plus a captcha-form POST is a second-tab submit, not origin traffic.
	if b.captchaClient.Check(req.Request, req.remoteIP) {
		if b.captchaClient.IsCaptchaFormPost(req.Request) {
			b.captchaClient.WriteSolvedRedirect(rw, req.Request)
			return
		}
		b.handleNextServeHTTP(rw, req)
		return
	}

	b.recordDropped(origin, req.ipType, "captcha")
	b.captchaClient.ServeHTTP(rw, req.Request, req.remoteIP)
}

// handleNextServeHTTP runs AppSec if enabled, then the next handler.
func (b *Bouncer) handleNextServeHTTP(rw http.ResponseWriter, req clientRequest) {
	if b.appsecEnabled && b.applyAppsecServeHTTP(rw, req) {
		return
	}
	b.next.ServeHTTP(rw, req.Request)
}

// applyAppsecServeHTTP queries AppSec and writes a remediation when the request must not reach origin.
func (b *Bouncer) applyAppsecServeHTTP(rw http.ResponseWriter, req clientRequest) bool {
	pol := appsec.Policy{
		FailureAction: b.appsecFailureAction,
	}
	decision, err := b.appsecClient.Query(req.remoteIP, req.Request, pol)
	if errors.Is(err, appsec.ErrFailureCaptcha) {
		b.handleRemediationServeHTTP(rw, req, decisionscope.CaptchaValue, lapi.OriginPluginAppsecFailure)
		return true
	}
	if err != nil {
		b.log.Debug("handleNextServeHTTP", "ip", req.remoteIP, "isWaf", true, "error", err)
		b.handleBanServeHTTP(rw, req, configuration.ReasonAPPSEC, lapi.OriginPluginAppsecFailure)
		return true
	}
	if decision == nil || decision.Action == "" || decision.Action == appsec.ActionAllow {
		return false
	}
	switch decision.Action {
	case appsec.ActionBan:
		b.handleBanServeHTTP(rw, req, configuration.ReasonAPPSEC, "appsec")
		return true
	case appsec.ActionChallenge:
		if decision.UserBodyContent == "" {
			b.handleBanServeHTTP(rw, req, configuration.ReasonAPPSEC, "appsec")
			return true
		}
	}
	b.handleAppsecResponseServeHTTP(rw, req, decision)
	return true
}

// handleAppsecResponseServeHTTP writes a structured AppSec envelope (challenge HTML, cookies, headers) to the client.
func (b *Bouncer) handleAppsecResponseServeHTTP(rw http.ResponseWriter, req clientRequest, decision *appsec.Response) {
	b.recordDropped("appsec", req.ipType, "")

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
		rw.Header().Set(b.remediationCustomHeader, decision.Action)
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
		b.log.Warn("handleAppsecResponseServeHTTP could not write appsec response", "ip", req.remoteIP, "error", err)
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

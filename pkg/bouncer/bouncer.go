// Package bouncer is the per-router Crowdsec handler Traefik gets back from New.
package bouncer

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
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
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/reclaim"
)

// Bouncer is one Traefik router handler. It is not the reclaim value.
type Bouncer struct {
	appsecBound              atomic.Value // *appsec.Client; typed nil when empty
	appsecFailureAction      string
	banTemplate              *template.Template
	banTemplateContentType   string
	captchaClient            *captcha.Client
	clientPoolStrategy       *ip.PoolStrategy
	decisionScopeHeaders     map[string]string // CrowdSec header scope → request header
	forcedDecisionHeader     string            // crowdsecDecisionHeader; empty = off
	enabled                  bool
	forwardedCustomHeader    string
	forwardedHeadersInsecure bool
	lapiBound                atomic.Value // *lapi.Client; typed nil when empty
	lapiFailureAction        string       // per-router LAPI fallback (not on Client identity)
	lapiInstanceName         string
	appsecInstanceName       string
	subscribeLAPI            bool
	subscribeAppSec          bool
	streamStartupBlock       bool
	redisUnreachableBlock    bool  // per-router Redis fail-closed
	defaultDecisionSeconds   int64 // per-router live-cache TTL passed into LiveLookup
	log                      *slog.Logger
	bindingMu                sync.Mutex
	lapiReceived             *lapi.Client
	appsecReceived           *appsec.Client
	lapiReceiveSeen          bool
	appsecReceiveSeen        bool
	name                     string
	next                     http.Handler
	remediationCustomHeader  string
	remediationStatusCode    int
	serverPoolStrategy       *ip.PoolStrategy
	template                 *template.Template
	traceCustomHeader        string
	originBasedDecisionRemap map[string]map[string]string // per-router apply; LAPI/store keep original kinds
}

const msgBackendMissing = "crowdsec bouncer backend missing"

// remediationHeaderClientDisconnected is the RemediationHeadersCustomName value when the client
// dropped the body during AppSec buffering. Not a ban.
const remediationHeaderClientDisconnected = "error:client-disconnected"

// New returns a per-router handler. Clients arrive later through ReceiveLAPI and ReceiveAppSec.
func New(next http.Handler, name string, config *configuration.Config, subscribeLAPI, subscribeAppSec bool, log *slog.Logger) (*Bouncer, error) {
	log = log.With("traefikName", name)
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
		appsecFailureAction:      configuration.EffectiveFailureAction(config.CrowdsecAppsecFailureAction),
		banTemplate:              banTemplate,
		banTemplateContentType:   banTemplateContentType,
		captchaClient:            &captcha.Client{},
		clientPoolStrategy:       &ip.PoolStrategy{Checker: clientChecker},
		decisionScopeHeaders:     decisionscope.NormalizeDecisionScopeHeaders(config.DecisionScopeHeaders),
		forcedDecisionHeader:     strings.TrimSpace(config.CrowdsecDecisionHeader),
		enabled:                  config.Enabled,
		forwardedCustomHeader:    forwardedCustomHeader,
		forwardedHeadersInsecure: config.ForwardedHeadersInsecure,
		lapiFailureAction:        configuration.EffectiveFailureAction(config.CrowdsecLapiFailureAction),
		lapiInstanceName:         config.CrowdsecLapiInstanceName,
		appsecInstanceName:       config.CrowdsecAppsecInstanceName,
		subscribeLAPI:            subscribeLAPI,
		subscribeAppSec:          subscribeAppSec,
		streamStartupBlock:       config.StreamStartupBlock,
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
	routeHandler.log.Debug("Bouncer initialized")
	return routeHandler, nil
}

func (b *Bouncer) loadedLAPI() *lapi.Client {
	client, _ := reclaim.Unbox(&b.lapiBound).(*lapi.Client)
	return client
}

func (b *Bouncer) loadedAppSec() *appsec.Client {
	stored := reclaim.Unbox(&b.appsecBound)
	client, _ := stored.(*appsec.Client)
	return client
}

// ReceiveLAPI stores the published LAPI client and validates it.
// published is a reclaim.Published. The same pointer is a no-op.
func (b *Bouncer) ReceiveLAPI(published any) {
	if !b.subscribeLAPI {
		return
	}
	notice, _ := published.(reclaim.Published)
	b.storeBinding(&b.lapiBound, notice.Value)
	b.receiveLAPI()
}

// ReceiveAppSec stores the published AppSec client.
// published is a reclaim.Published. The same pointer is a no-op.
func (b *Bouncer) ReceiveAppSec(published any) {
	if !b.subscribeAppSec {
		return
	}
	notice, _ := published.(reclaim.Published)
	b.storeBinding(&b.appsecBound, notice.Value)
	b.receiveAppSec()
}

func (b *Bouncer) storeBinding(dest *atomic.Value, value any) {
	prev := dest.Load()
	if boxed, ok := prev.(*reclaim.Box); ok {
		boxed.Value = value
		return
	}
	dest.Store(&reclaim.Box{Value: value})
}

func (b *Bouncer) receiveLAPI() {
	current := b.loadedLAPI()
	b.bindingMu.Lock()
	defer b.bindingMu.Unlock()
	if b.lapiReceiveSeen && current == b.lapiReceived {
		return
	}
	previous := b.lapiReceived
	b.lapiReceived = current
	b.lapiReceiveSeen = true
	if previous != nil && previous != current {
		b.log.Debug("crowdsec bouncer unbound",
			"traefikName", b.name,
			"leg", "lapi",
			"instanceName", b.lapiInstanceName,
			"incarnation", previous.Incarnation(),
		)
	}
	if current == nil {
		if previous == nil {
			b.log.Debug("crowdsec bouncer unbound",
				"traefikName", b.name,
				"leg", "lapi",
				"instanceName", b.lapiInstanceName,
			)
		}
		return
	}
	missing := decisionscope.MissingStreamScopes(b.decisionScopeHeaders, current.StreamScopes())
	if len(missing) > 0 {
		b.log.Warn("crowdsec bouncer stream scopes missing",
			"traefikName", b.name,
			"missing", strings.Join(missing, ","),
		)
	}
	b.log.Info("crowdsec bouncer bound",
		"traefikName", b.name,
		"leg", "lapi",
		"instanceName", b.lapiInstanceName,
		"incarnation", current.Incarnation(),
	)
}

func (b *Bouncer) receiveAppSec() {
	current := b.loadedAppSec()
	b.bindingMu.Lock()
	defer b.bindingMu.Unlock()
	if b.appsecReceiveSeen && current == b.appsecReceived {
		return
	}
	previous := b.appsecReceived
	b.appsecReceived = current
	b.appsecReceiveSeen = true
	if previous != nil && previous != current {
		b.log.Debug("crowdsec bouncer unbound",
			"traefikName", b.name,
			"leg", "appsec",
			"instanceName", b.appsecInstanceName,
			"incarnation", previous.Incarnation(),
		)
	}
	if current == nil {
		if previous == nil {
			b.log.Debug("crowdsec bouncer unbound",
				"traefikName", b.name,
				"leg", "appsec",
				"instanceName", b.appsecInstanceName,
			)
		}
		return
	}
	b.log.Info("crowdsec bouncer bound",
		"traefikName", b.name,
		"leg", "appsec",
		"instanceName", b.appsecInstanceName,
		"incarnation", current.Incarnation(),
	)
}

func (b *Bouncer) warnBackendMissing(leg, instanceName string) {
	b.log.Warn(msgBackendMissing, "leg", leg, "instanceName", instanceName)
}

// LapiClient is the bound LAPI backend this route uses, or nil.
func (b *Bouncer) LapiClient() *lapi.Client {
	return b.loadedLAPI()
}

// SameLapiClient reports whether two routes share one LAPI client pointer.
func (b *Bouncer) SameLapiClient(other *Bouncer) bool {
	return other != nil && b.loadedLAPI() == other.loadedLAPI()
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
//nolint:gocyclo,gocognit,funlen
func (b *Bouncer) ServeHTTP(rw http.ResponseWriter, httpReq *http.Request) {
	if !b.enabled {
		b.next.ServeHTTP(rw, httpReq)
		return
	}

	if b.streamStartupBlock {
		if b.subscribeLAPI && b.loadedLAPI() == nil {
			b.warnBackendMissing("lapi", b.lapiInstanceName)
			rw.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if b.subscribeAppSec && b.loadedAppSec() == nil {
			b.warnBackendMissing("appsec", b.appsecInstanceName)
			rw.WriteHeader(http.StatusServiceUnavailable)
			return
		}
	}

	lapiClient := b.loadedLAPI()
	crowdsecMode := ""
	if lapiClient != nil {
		crowdsecMode = lapiClient.Mode()
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

	if b.subscribeLAPI && lapiClient == nil {
		b.applyLapiFailureAction(rw, req, configuration.ReasonLAPI, lapi.OriginPluginLapiFailure)
		return
	}
	if !b.subscribeLAPI {
		b.passOrForcedCaptcha(rw, req)
		return
	}

	// Mapped scope headers for this request. Missing headers are omitted.
	scopes := decisionscope.RequestScopeValues(b.decisionScopeHeaders, req.Request)

	// live, stream, and alone consult the cache.
	if crowdsecMode == configuration.LiveMode || crowdsecMode == configuration.StreamMode || crowdsecMode == configuration.AloneMode {
		var kind, origin string
		var originID uint16
		var lookupErr error
		kind, origin, originID, lookupErr = lapiClient.LookupRemediation(req.remoteIP, req.ipAddr, scopes)
		if lookupErr != nil {
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

	if crowdsecMode == configuration.StreamMode || crowdsecMode == configuration.AloneMode {
		if lapiClient.StreamHealthy() {
			b.passOrForcedCaptcha(rw, req)
			// No decision affecting this IP.
			return
		}
		b.log.Debug("ServeHTTP", "isCrowdsecStreamHealthy", false, "ip", req.remoteIP)
		b.applyLapiFailureAction(rw, req, configuration.ReasonTECH, lapi.OriginPluginTechStreamFail)
		// Stream/alone never query LAPI per request. Miss is allow or failure action.
		return
	}

	if crowdsecMode == configuration.LiveMode || crowdsecMode == configuration.NoneMode {
		kind, origin, err := lapiClient.LiveLookup(req.remoteIP, scopes, b.defaultDecisionSeconds)
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
	if client := b.loadedLAPI(); client != nil {
		client.IncProcessed(ipType)
	}
}

// recordDropped counts a remediating response on the connection usage-metrics window.
func (b *Bouncer) recordDropped(origin, ipType, remediation string) {
	if client := b.loadedLAPI(); client != nil {
		client.IncDropped(origin, ipType, remediation)
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

// handleClientDisconnectedServeHTTP stops the request without a ban when the client dropped the body.
func (b *Bouncer) handleClientDisconnectedServeHTTP(rw http.ResponseWriter, req clientRequest) {
	logger.Trace(b.log, "client disconnected while buffering AppSec body", "ip", req.remoteIP)
	if b.remediationCustomHeader != "" {
		rw.Header().Set(b.remediationCustomHeader, remediationHeaderClientDisconnected)
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
	if b.subscribeAppSec && b.applyAppsecServeHTTP(rw, req) {
		return
	}
	b.next.ServeHTTP(rw, req.Request)
}

// applyAppsecServeHTTP queries AppSec and writes a remediation when the request must not reach origin.
func (b *Bouncer) applyAppsecServeHTTP(rw http.ResponseWriter, req clientRequest) bool {
	appsecClient := b.loadedAppSec()
	if appsecClient == nil {
		switch b.appsecFailureAction {
		case configuration.FailureActionPassthrough:
			return false
		case configuration.FailureActionCaptcha:
			b.handleRemediationServeHTTP(rw, req, decisionscope.CaptchaValue, lapi.OriginPluginAppsecFailure)
			return true
		default:
			b.handleBanServeHTTP(rw, req, configuration.ReasonAPPSEC, lapi.OriginPluginAppsecFailure)
			return true
		}
	}
	pol := appsec.Policy{
		FailureAction: b.appsecFailureAction,
	}
	decision, err := appsecClient.Query(req.remoteIP, req.Request, pol)
	if errors.Is(err, appsec.ErrClientDisconnected) {
		b.handleClientDisconnectedServeHTTP(rw, req)
		return true
	}
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

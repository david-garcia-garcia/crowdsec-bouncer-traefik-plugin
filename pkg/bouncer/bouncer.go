// Package bouncer is the per-router Crowdsec handler Traefik gets back from New.
package bouncer

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"text/template"
	"time"

	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/appsec"
	cache "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
	captcha "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/captcha"
	configuration "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
	ip "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/ip"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/lapi"
)

// Bouncer is one Traefik router handler. It is not the reclaim value.
type Bouncer struct {
	appsecClient            *appsec.Client
	appsecEnabled           bool
	appsecFailureAction     string
	banTemplate             *template.Template
	banTemplateContentType  string
	captchaClient           *captcha.Client
	clientPoolStrategy      *ip.PoolStrategy
	crowdsecMode            string
	decisionScopeHeaders    map[string]string // CrowdSec header scope → request header
	enabled                 bool
	forwardedCustomHeader   string
	lapiClient              *lapi.Client
	log                     *slog.Logger
	name                    string
	next                    http.Handler
	remediationCustomHeader string
	remediationStatusCode   int
	serverPoolStrategy      *ip.PoolStrategy
	template                *template.Template
	traceCustomHeader       string
}

// New returns a per-router handler bound to lapiClient and appsecClient.
func New(next http.Handler, name string, config *configuration.Config, lapiClient *lapi.Client, appsecClient *appsec.Client, log *slog.Logger) (http.Handler, error) {
	serverChecker, _ := ip.NewChecker(log, config.ForwardedHeadersTrustedIPs)
	clientChecker, _ := ip.NewChecker(log, config.ClientTrustedIPs)

	var banTemplate *template.Template
	var banTemplateContentType string
	if config.BanFilePath != "" {
		banTemplate, banTemplateContentType, _ = configuration.GetTemplate(config.BanFilePath)
	}

	routeHandler := &Bouncer{
		appsecClient:            appsecClient,
		appsecEnabled:           config.CrowdsecAppsecEnabled,
		appsecFailureAction:     configuration.EffectiveFailureAction(config.CrowdsecAppsecFailureAction),
		banTemplate:             banTemplate,
		banTemplateContentType:  banTemplateContentType,
		captchaClient:           &captcha.Client{},
		clientPoolStrategy:      &ip.PoolStrategy{Checker: clientChecker},
		crowdsecMode:            config.CrowdsecMode,
		decisionScopeHeaders:    decisionscope.NormalizeDecisionScopeHeaders(config.DecisionScopeHeaders),
		enabled:                 config.Enabled,
		forwardedCustomHeader:   config.ForwardedHeadersCustomName,
		lapiClient:              lapiClient,
		log:                     log,
		name:                    name,
		next:                    next,
		remediationCustomHeader: config.RemediationHeadersCustomName,
		remediationStatusCode:   config.RemediationStatusCode,
		serverPoolStrategy:      &ip.PoolStrategy{Checker: serverChecker},
		template:                template.New("CrowdsecBouncer").Delims("[[", "]]"),
		traceCustomHeader:       config.TraceHeadersCustomName,
	}
	if config.CrowdsecMode == configuration.AppsecMode {
		routeHandler.log.Debug("Bouncer initialized name:" + name)
		return routeHandler, nil
	}
	config.CaptchaSiteKey, _ = configuration.GetVariable(config, "CaptchaSiteKey")
	config.CaptchaSecretKey, _ = configuration.GetVariable(config, "CaptchaSecretKey")
	err := routeHandler.captchaClient.New(
		log,
		lapiClient.Cache(),
		&http.Client{
			Transport: &http.Transport{MaxIdleConns: 10, MaxIdleConnsPerHost: 10, IdleConnTimeout: 30 * time.Second},
			Timeout:   time.Duration(config.HTTPTimeoutSeconds) * time.Second,
		},
		config.CaptchaProvider,
		config.CaptchaCustomJsURL,
		config.CaptchaCustomKey,
		config.CaptchaCustomResponse,
		config.CaptchaCustomValidateURL,
		config.CaptchaSiteKey,
		config.CaptchaSecretKey,
		config.RemediationHeadersCustomName,
		config.CaptchaFilePath,
		config.CaptchaGracePeriodSeconds,
	)
	if err != nil {
		log.Error("CaptchaClient not valid " + err.Error())
		return nil, err
	}
	routeHandler.log.Debug("Bouncer initialized name:" + name)
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

	remoteIP, ipAddr, err := ip.GetRemoteIP(httpReq, b.serverPoolStrategy, b.forwardedCustomHeader)
	req := clientRequest{
		Request:  httpReq,
		ipAddr:   ipAddr,
		ipType:   ip.FamilyOfIP(ipAddr),
		remoteIP: remoteIP,
	}
	b.recordProcessed(req.ipType)
	if err != nil {
		b.log.Error(fmt.Sprintf("ServeHTTP:getRemoteIp ip:%s %s", req.remoteIP, err.Error()))
		b.handleBanServeHTTP(rw, req, configuration.ReasonTECH, lapi.OriginPluginTechGetRemoteFail)
		return
	}
	if req.ipAddr == nil {
		b.log.Error(fmt.Sprintf("ServeHTTP:parseClientIP ip:%s", req.remoteIP))
		b.handleBanServeHTTP(rw, req, configuration.ReasonTECH, lapi.OriginPluginTechTrustIPFail)
		return
	}
	isTrusted := b.clientPoolStrategy.Checker.ContainsIP(req.ipAddr)
	b.log.Debug(fmt.Sprintf("ServeHTTP ip:%s isTrusted:%v", req.remoteIP, isTrusted))
	if isTrusted {
		b.next.ServeHTTP(rw, req.Request)
		// Trusted clients skip LAPI and AppSec.
		return
	}

	if b.crowdsecMode == configuration.AppsecMode {
		b.handleNextServeHTTP(rw, req)
		return
	}

	// Mapped scope headers for this request. Missing headers are omitted.
	scopes := decisionscope.RequestScopeValues(b.decisionScopeHeaders, req.Request)

	// live, stream, and alone consult the cache.
	if b.crowdsecMode == configuration.LiveMode || b.crowdsecMode == configuration.StreamMode || b.crowdsecMode == configuration.AloneMode {
		value, origin, cacheErr := decisionscope.LookupCachedRemediation(b.lapiClient.Cache(), req.remoteIP, req.ipAddr, scopes, b.lapiClient.RangeMembership())
		switch {
		case cacheErr != nil:
			cacheErrString := cacheErr.Error()
			b.log.Debug(fmt.Sprintf("ServeHTTP:Get ip:%s cache:%s", req.remoteIP, cacheErrString))
			if cacheErrString == cache.CacheUnreachable && !b.lapiClient.RedisUnreachableBlock() {
				b.log.Error(fmt.Sprintf("ServeHTTP:Get ip:%s redisUnreachable=true", req.remoteIP))
				b.handleNextServeHTTP(rw, req)
				return
			}
			if cacheErrString == cache.CacheMiss {
				break
			}
			b.log.Error(fmt.Sprintf("ServeHTTP:Get ip:%s %s", req.remoteIP, cacheErrString))
			b.handleBanServeHTTP(rw, req, configuration.ReasonTECH, lapi.OriginPluginTechCacheFail)
			return
		case decisionscope.IsActiveRemediation(value):
			b.log.Debug(fmt.Sprintf("ServeHTTP ip:%s cache:hit remediation:%s", req.remoteIP, value))
			b.handleRemediationServeHTTP(rw, req, value, origin)
			return
		case value == cache.NoBannedValue:
			b.handleNextServeHTTP(rw, req)
			return
		}
	}

	if b.crowdsecMode == configuration.StreamMode || b.crowdsecMode == configuration.AloneMode {
		if b.lapiClient.StreamHealthy() {
			b.handleNextServeHTTP(rw, req)
			// No decision affecting this IP.
			return
		}
		b.log.Debug(fmt.Sprintf("ServeHTTP isCrowdsecStreamHealthy:false ip:%s", req.remoteIP))
		b.applyLapiFailureAction(rw, req, configuration.ReasonTECH, lapi.OriginPluginTechStreamFail)
		// Stream/alone never query LAPI per request. Miss is allow or failure action.
		return
	}

	if b.crowdsecMode == configuration.LiveMode || b.crowdsecMode == configuration.NoneMode {
		value, err := b.lapiClient.LiveLookup(req.remoteIP, scopes)
		kind := cache.RemediationKind(value)
		origin := cache.RemediationOrigin(value)
		if err != nil {
			b.log.Debug("ServeHTTP:LiveLookup " + err.Error())
			if !decisionscope.IsActiveRemediation(kind) {
				b.applyLapiFailureAction(rw, req, configuration.ReasonLAPI, lapi.OriginPluginLapiFailure)
				return
			}
		}
		if kind == cache.NoBannedValue {
			b.handleNextServeHTTP(rw, req)
			return
		}
		b.log.Debug(fmt.Sprintf("ServeHTTP:LiveLookup ip:%s isBanned:%v", req.remoteIP, kind))
		b.handleRemediationServeHTTP(rw, req, kind, origin)
	}
}

// applyLapiFailureAction remediates a live LAPI error or stream-unhealthy cache miss.
func (b *Bouncer) applyLapiFailureAction(rw http.ResponseWriter, req clientRequest, banReason, origin string) {
	switch b.lapiClient.LapiFailureAction() {
	case configuration.FailureActionPassthrough:
		b.handleNextServeHTTP(rw, req)
	case configuration.FailureActionCaptcha:
		b.handleRemediationServeHTTP(rw, req, cache.CaptchaValue, origin)
	default:
		b.handleBanServeHTTP(rw, req, banReason, origin)
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
		headerVal := req.Header.Get(b.traceCustomHeader)
		if headerVal != "" {
			templateData["TraceID"] = headerVal
		}
	}

	err := b.banTemplate.Execute(rw, templateData)
	if err != nil {
		b.log.Warn("handleBanServeHTTP could not write template to ResponseWriter: " + err.Error())
	}
}

// handleRemediationServeHTTP applies captcha or ban for a cached or live verdict.
func (b *Bouncer) handleRemediationServeHTTP(rw http.ResponseWriter, req clientRequest, remediation, origin string) {
	kind := cache.RemediationKind(remediation)
	b.log.Debug(fmt.Sprintf("handleRemediationServeHTTP ip:%s remediation:%s", req.remoteIP, kind))
	if b.captchaClient.Valid && kind == cache.CaptchaValue && req.Method != http.MethodHead {
		if b.captchaClient.Check(req.remoteIP) {
			// Duplicate captcha form POST after grace must 302, not reach origin.
			if b.captchaClient.IsCaptchaFormPost(req.Request) {
				b.captchaClient.WriteSolvedRedirect(rw, req.Request)
				return
			}
			b.handleNextServeHTTP(rw, req)
			return
		}
		b.recordDropped(origin, req.ipType, "captcha")
		b.captchaClient.ServeHTTP(rw, req.Request, req.remoteIP)
		return
	}
	b.handleBanServeHTTP(rw, req, configuration.ReasonLAPI, origin)
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
		b.handleRemediationServeHTTP(rw, req, cache.CaptchaValue, lapi.OriginPluginAppsecFailure)
		return true
	}
	if err != nil {
		b.log.Debug(fmt.Sprintf("handleNextServeHTTP ip:%s isWaf:true %s", req.remoteIP, err.Error()))
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
		b.log.Warn(fmt.Sprintf("handleAppsecResponseServeHTTP ip:%s could not write appsec response: %s", req.remoteIP, err.Error()))
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

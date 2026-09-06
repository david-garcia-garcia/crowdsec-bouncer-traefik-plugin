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

	cache "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
	captcha "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/captcha"
	configuration "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/crowdsecconnection"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
	ip "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/ip"
)

// Bouncer is one Traefik router handler. It is not the reclaim value.
type Bouncer struct {
	next     http.Handler
	name     string
	template *template.Template

	enabled                 bool
	appsecEnabled           bool
	appsecFailureAction     string
	remediationStatusCode   int
	remediationCustomHeader string
	forwardedCustomHeader   string
	banTemplate             *template.Template
	banTemplateContentType  string
	traceCustomHeader       string
	clientPoolStrategy      *ip.PoolStrategy
	serverPoolStrategy      *ip.PoolStrategy
	captchaClient           *captcha.Client
	log                     *slog.Logger
	conn                    *crowdsecconnection.CrowdsecConnection
	decisionScopeHeaders    map[string]string // CrowdSec header scope → request header
}

// New returns a per-router handler bound to conn.
func New(next http.Handler, name string, config *configuration.Config, conn *crowdsecconnection.CrowdsecConnection, log *slog.Logger) (http.Handler, error) {
	serverChecker, _ := ip.NewChecker(log, config.ForwardedHeadersTrustedIPs)
	clientChecker, _ := ip.NewChecker(log, config.ClientTrustedIPs)

	var banTemplate *template.Template
	var banTemplateContentType string
	if config.BanFilePath != "" {
		banTemplate, banTemplateContentType, _ = configuration.GetTemplate(config.BanFilePath)
	}

	routeHandler := &Bouncer{
		next:                    next,
		name:                    name,
		template:                template.New("CrowdsecBouncer").Delims("[[", "]]"),
		enabled:                 config.Enabled,
		appsecEnabled:           config.CrowdsecAppsecEnabled,
		appsecFailureAction:     configuration.EffectiveFailureAction(config.CrowdsecAppsecFailureAction),
		remediationCustomHeader: config.RemediationHeadersCustomName,
		forwardedCustomHeader:   config.ForwardedHeadersCustomName,
		remediationStatusCode:   config.RemediationStatusCode,
		banTemplate:             banTemplate,
		banTemplateContentType:  banTemplateContentType,
		traceCustomHeader:       config.TraceHeadersCustomName,
		log:                     log,
		conn:                    conn,
		decisionScopeHeaders:    decisionscope.NormalizeDecisionScopeHeaders(config.DecisionScopeHeaders),
		serverPoolStrategy:      &ip.PoolStrategy{Checker: serverChecker},
		clientPoolStrategy:      &ip.PoolStrategy{Checker: clientChecker},
		captchaClient:           &captcha.Client{},
	}
	if config.CrowdsecMode == configuration.AppsecMode {
		routeHandler.log.Debug("Bouncer initialized name:" + name)
		return routeHandler, nil
	}
	config.CaptchaSiteKey, _ = configuration.GetVariable(config, "CaptchaSiteKey")
	config.CaptchaSecretKey, _ = configuration.GetVariable(config, "CaptchaSecretKey")
	err := routeHandler.captchaClient.New(
		log,
		conn.Cache(),
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

// Connection is the reclaimed CrowdsecConnection this route uses.
func (b *Bouncer) Connection() *crowdsecconnection.CrowdsecConnection {
	return b.conn
}

// SameConnection reports whether two routes share one CrowdsecConnection pointer.
func (b *Bouncer) SameConnection(other *Bouncer) bool {
	return other != nil && b.conn == other.conn
}

// ServeHTTP is the per-router middleware handler.
//
//nolint:nestif
func (b *Bouncer) ServeHTTP(rw http.ResponseWriter, httpReq *http.Request) {
	if !b.enabled {
		b.next.ServeHTTP(rw, httpReq)
		return
	}

	remoteIP, ipAddr, err := ip.GetRemoteIP(httpReq, b.serverPoolStrategy, b.forwardedCustomHeader)
	req := clientRequest{
		Request:  httpReq,
		remoteIP: remoteIP,
		ipAddr:   ipAddr,
		ipType:   ip.FamilyOfIP(ipAddr),
	}
	b.recordProcessed(req.ipType)
	if err != nil {
		b.log.Error(fmt.Sprintf("ServeHTTP:getRemoteIp ip:%s %s", req.remoteIP, err.Error()))
		b.handleBanServeHTTP(rw, req, configuration.ReasonTECH, crowdsecconnection.OriginPluginTechGetRemoteFail)
		return
	}
	if req.ipAddr == nil {
		b.log.Error(fmt.Sprintf("ServeHTTP:parseClientIP ip:%s", req.remoteIP))
		b.handleBanServeHTTP(rw, req, configuration.ReasonTECH, crowdsecconnection.OriginPluginTechTrustIPFail)
		return
	}
	isTrusted := b.clientPoolStrategy.Checker.ContainsIP(req.ipAddr)
	b.log.Debug(fmt.Sprintf("ServeHTTP ip:%s isTrusted:%v", req.remoteIP, isTrusted))
	if isTrusted {
		b.next.ServeHTTP(rw, req.Request)
		return
	}

	if b.conn.Mode() == configuration.AppsecMode {
		b.handleNextServeHTTP(rw, req)
		return
	}

	// Mapped scope headers for this request. Missing headers are omitted.
	scopes := decisionscope.RequestScopeValues(b.decisionScopeHeaders, req.Request)

	if b.conn.Mode() != configuration.NoneMode {
		value, origin, cacheErr := decisionscope.LookupCachedRemediation(b.conn.Cache(), b.conn.Mode(), req.remoteIP, req.ipAddr, scopes, b.conn.RangeMembership())
		switch {
		case cacheErr != nil:
			cacheErrString := cacheErr.Error()
			b.log.Debug(fmt.Sprintf("ServeHTTP:Get ip:%s cache:%s", req.remoteIP, cacheErrString))
			if !b.conn.RedisUnreachableBlock() && cacheErrString == cache.CacheUnreachable {
				b.log.Error(fmt.Sprintf("ServeHTTP:Get ip:%s redisUnreachable=true", req.remoteIP))
				b.handleNextServeHTTP(rw, req)
				return
			}
			if cacheErrString != cache.CacheMiss {
				b.log.Error(fmt.Sprintf("ServeHTTP:Get ip:%s %s", req.remoteIP, cacheErrString))
				b.handleBanServeHTTP(rw, req, configuration.ReasonTECH, crowdsecconnection.OriginPluginTechCacheFail)
				return
			}
		case decisionscope.IsActiveRemediation(value):
			b.log.Debug(fmt.Sprintf("ServeHTTP ip:%s cache:hit remediation:%s", req.remoteIP, value))
			b.handleRemediationServeHTTP(rw, req, value, origin)
			return
		case value == cache.NoBannedValue:
			b.handleNextServeHTTP(rw, req)
			return
		}
	}

	if b.conn.Mode() == configuration.StreamMode || b.conn.Mode() == configuration.AloneMode {
		if b.conn.StreamHealthy() {
			b.handleNextServeHTTP(rw, req)
		} else {
			b.log.Debug(fmt.Sprintf("ServeHTTP isCrowdsecStreamHealthy:false ip:%s", req.remoteIP))
			b.applyLapiFailureAction(rw, req, configuration.ReasonTECH, crowdsecconnection.OriginPluginTechStreamFail)
		}
	} else {
		value, err := b.conn.LiveLookup(req.remoteIP, scopes)
		kind := cache.RemediationKind(value)
		origin := cache.RemediationOrigin(value)
		if err != nil && !decisionscope.IsActiveRemediation(kind) {
			b.log.Debug("ServeHTTP:LiveLookup " + err.Error())
			b.applyLapiFailureAction(rw, req, configuration.ReasonLAPI, crowdsecconnection.OriginPluginLapiFailure)
			return
		}
		if err != nil {
			b.log.Debug("ServeHTTP:LiveLookup " + err.Error())
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
	switch b.conn.LapiFailureAction() {
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
	if b.conn != nil {
		b.conn.IncProcessed(ipType)
	}
}

// recordDropped counts a remediating response on the connection usage-metrics window.
func (b *Bouncer) recordDropped(origin, ipType, remediation string) {
	if b.conn != nil {
		b.conn.IncDropped(origin, ipType, remediation)
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
	pol := crowdsecconnection.AppsecPolicy{
		FailureAction: b.appsecFailureAction,
	}
	decision, err := b.conn.AppsecQuery(req.remoteIP, req.Request, pol)
	if errors.Is(err, crowdsecconnection.ErrFailureCaptcha) {
		b.handleRemediationServeHTTP(rw, req, cache.CaptchaValue, crowdsecconnection.OriginPluginAppsecFailure)
		return true
	}
	if err != nil {
		b.log.Debug(fmt.Sprintf("handleNextServeHTTP ip:%s isWaf:true %s", req.remoteIP, err.Error()))
		b.handleBanServeHTTP(rw, req, configuration.ReasonAPPSEC, crowdsecconnection.OriginPluginAppsecFailure)
		return true
	}
	if decision == nil || decision.Action == "" || decision.Action == crowdsecconnection.AppsecActionAllow {
		return false
	}
	switch decision.Action {
	case crowdsecconnection.AppsecActionBan:
		b.handleBanServeHTTP(rw, req, configuration.ReasonAPPSEC, "appsec")
		return true
	case crowdsecconnection.AppsecActionChallenge:
		if decision.UserBodyContent == "" {
			b.handleBanServeHTTP(rw, req, configuration.ReasonAPPSEC, "appsec")
			return true
		}
	}
	b.handleAppsecResponseServeHTTP(rw, req, decision)
	return true
}

// handleAppsecResponseServeHTTP writes a structured AppSec envelope (challenge HTML, cookies, headers) to the client.
func (b *Bouncer) handleAppsecResponseServeHTTP(rw http.ResponseWriter, req clientRequest, decision *crowdsecconnection.AppsecResponse) {
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

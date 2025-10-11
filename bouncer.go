// Package crowdsec_bouncer_traefik_plugin implements a middleware that communicates with crowdsec.
// It can cache results in memory or using redis, or even ask crowdsec for every requests.
package crowdsec_bouncer_traefik_plugin //nolint:revive,stylecheck

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"text/template"
	"time"

	cache "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
	captcha "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/captcha"
	configuration "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	crowdsec "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/crowdsec"
	decision "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/decision"
	ip "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/ip"
	logger "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

const (
	crowdsecAppsecIPHeader   = "X-Crowdsec-Appsec-Ip"
	crowdsecAppsecURIHeader  = "X-Crowdsec-Appsec-Uri"
	crowdsecAppsecHostHeader = "X-Crowdsec-Appsec-Host"
	crowdsecAppsecVerbHeader = "X-Crowdsec-Appsec-Verb"
	crowdsecAppsecHeader     = "X-Crowdsec-Appsec-Api-Key"
	crowdsecAppsecUserAgent  = "X-Crowdsec-Appsec-User-Agent"
	crowdsecLapiHeader       = "X-Api-Key"
	crowdsecLapiRoute        = "v1/decisions"
	crowdsecLapiStreamRoute  = "v1/decisions/stream"
	crowdsecLapiMetricsRoute = "v1/usage-metrics"
	crowdsecCapiHost         = "api.crowdsec.net"
	crowdsecCapiHeader       = "Authorization"
	crowdsecCapiLoginRoute   = "v2/watchers/login"
	crowdsecCapiStreamRoute  = "v2/decisions/stream"
	cacheTimeoutKey          = "updated"
)

// ##############################################################
// Important: traefik creates an instance of the bouncer per route.
// We rely on globals (both here and in the memory cache) to share info between
// routes. This means that some of the plugins parameters will only work "once"
// and will take the values of the first middleware that was instantiated even
// if you have different middlewares with different parameters. This design
// makes it impossible to have multiple crowdsec implementations per cluster (unless you have multiple traefik deployments in it)
// - updateInterval
// - updateMaxFailure
// - defaultDecisionTimeout
// - redisUnreachableBlock
// - appsecEnabled
// - appsecHost
// - metricsUpdateIntervalSeconds
// - others...
// ###################################

//nolint:gochecknoglobals
var (
	// Map of CrowdSec components by grouping key
	crowdsecComponents = make(map[string]*crowdsec.Component)
	// Map of cache clients by grouping key
	cacheClients = make(map[string]*cache.Client)
)

// CreateConfig creates the default plugin configuration.
func CreateConfig() *configuration.Config {
	return configuration.New()
}

// generateGroupingKey creates a grouping key for component sharing
func generateGroupingKey(config *configuration.Config) string {
	if config.GroupingKey != "" {
		return config.GroupingKey
	}

	// Default grouping key: lapihost+appsechost
	key := config.CrowdsecLapiHost
	if config.CrowdsecAppsecEnabled {
		key += "+" + config.CrowdsecAppsecHost
	}
	return key
}

// Bouncer a Bouncer struct.
type Bouncer struct {
	next     http.Handler
	name     string
	template *template.Template

	enabled                 bool
	crowdsecMode            string
	remediationStatusCode   int
	remediationCustomHeader string
	forwardedCustomHeader   string
	countryHeader           string
	asnHeader               string
	banTemplateString       string
	clientPoolStrategy      *ip.PoolStrategy
	serverPoolStrategy      *ip.PoolStrategy
	captchaClient           *captcha.Client
	crowdsecComponent       *crowdsec.Component
	log                     *logger.Log
}

// New creates the crowdsec bouncer plugin.
//
//nolint:gocyclo
func New(ctx context.Context, next http.Handler, config *configuration.Config, name string) (http.Handler, error) {
	config.LogLevel = strings.ToUpper(config.LogLevel)
	log := logger.New(config.LogLevel, config.LogFilePath)
	err := configuration.ValidateParams(config)
	if err != nil {
		log.Error("New:validateParams " + err.Error())
		return nil, err
	}

	serverChecker, _ := ip.NewChecker(log, config.ForwardedHeadersTrustedIPs)
	clientChecker, _ := ip.NewChecker(log, config.ClientTrustedIPs)

	var tlsConfig *tls.Config
	if config.CrowdsecMode == configuration.AloneMode {
		config.CrowdsecCapiMachineID, _ = configuration.GetVariable(config, "CrowdsecCapiMachineID")
		config.CrowdsecCapiPassword, _ = configuration.GetVariable(config, "CrowdsecCapiPassword")
		config.CrowdsecLapiScheme = configuration.HTTPS
		config.CrowdsecLapiHost = crowdsecCapiHost
		config.CrowdsecLapiPath = "/"
		config.CrowdsecAppsecEnabled = false
		config.UpdateIntervalSeconds = 7200 // 2 hours
	} else {
		tlsConfig, err = configuration.GetTLSConfigCrowdsec(config, log)
		if err != nil {
			log.Error("New:getTLSConfigCrowdsec fail to get tlsConfig " + err.Error())
			return nil, err
		}
		apiKey, errAPIKey := configuration.GetVariable(config, "CrowdsecLapiKey")
		if errAPIKey != nil && len(tlsConfig.Certificates) == 0 {
			log.Error("New:crowdsecLapiKey fail to get CrowdsecLapiKey and no client certificate setup " + errAPIKey.Error())
			return nil, errAPIKey
		}
		config.CrowdsecLapiKey = apiKey
	}

	var banTemplateString string
	if config.BanHTMLFilePath != "" {
		var buf bytes.Buffer
		banTemplate, _ := configuration.GetHTMLTemplate(config.BanHTMLFilePath)
		err = banTemplate.Execute(&buf, nil)
		if err != nil {
			log.Error("New:banTemplate is bad formatted " + err.Error())
			return nil, err
		}
		banTemplateString = buf.String()
	}

	// Create HTTP client
	httpClient := &http.Client{
		Transport: &http.Transport{
			MaxIdleConns:    10,
			IdleConnTimeout: 30 * time.Second,
			TLSClientConfig: tlsConfig,
		},
		Timeout: time.Duration(config.HTTPTimeoutSeconds) * time.Second,
	}

	// Generate grouping key for component sharing
	groupingKey := generateGroupingKey(config)

	// Get or create CrowdSec component for this grouping key
	var crowdsecComponent *crowdsec.Component
	var cacheClient *cache.Client

	if config.CrowdsecMode != configuration.AppsecMode {
		// Check if component already exists for this grouping key
		if existingComponent, exists := crowdsecComponents[groupingKey]; exists {
			crowdsecComponent = existingComponent
			cacheClient = cacheClients[groupingKey]
			log.Debug(fmt.Sprintf("Reusing existing CrowdSec component for grouping key: %s", groupingKey))
		} else {
			log.Debug(fmt.Sprintf("Creating new CrowdSec component for grouping key: %s", groupingKey))

			// Create cache client for this group
			config.RedisCachePassword, _ = configuration.GetVariable(config, "RedisCachePassword")
			cacheClient = &cache.Client{}
			cacheClient.New(
				log,
				config.RedisCacheEnabled,
				config.RedisCacheHost,
				config.RedisCachePassword,
				config.RedisCacheDatabase,
			)

			// Create AppSec config if enabled
			var appsecConfig *decision.AppSecConfig
			if config.CrowdsecAppsecEnabled {
				appsecConfig = &decision.AppSecConfig{
					Enabled:          config.CrowdsecAppsecEnabled,
					Host:             config.CrowdsecAppsecHost,
					Path:             config.CrowdsecAppsecPath,
					Scheme:           config.CrowdsecLapiScheme,
					Key:              config.CrowdsecLapiKey,
					BodyLimit:        config.CrowdsecAppsecBodyLimit,
					FailureBlock:     config.CrowdsecAppsecFailureBlock,
					UnreachableBlock: config.CrowdsecAppsecUnreachableBlock,
					HTTPClient:       httpClient,
				}
			}

			crowdsecConfig := &crowdsec.Config{
				Scheme:                       config.CrowdsecLapiScheme,
				Host:                         config.CrowdsecLapiHost,
				Path:                         config.CrowdsecLapiPath,
				Key:                          config.CrowdsecLapiKey,
				Mode:                         config.CrowdsecMode,
				MachineID:                    config.CrowdsecCapiMachineID,
				Password:                     config.CrowdsecCapiPassword,
				Scenarios:                    config.CrowdsecCapiScenarios,
				UpdateIntervalSeconds:        config.UpdateIntervalSeconds,
				UpdateMaxFailure:             config.UpdateMaxFailure,
				MetricsUpdateIntervalSeconds: config.MetricsUpdateIntervalSeconds,
				CountryHeader:                config.CountryHeader,
				ASNHeader:                    config.ASNHeader,
				AppSecConfig:                 appsecConfig,
				HTTPClient:                   httpClient,
			}

			crowdsecComponent, err = crowdsec.NewComponent(ctx, crowdsecConfig, log)
			if err != nil {
				log.Error("New:crowdsecComponent " + err.Error())
				return nil, err
			}

			// Initialize decision providers with cache client
			err = crowdsecComponent.InitializeProviders(cacheClient)
			if err != nil {
				log.Error("New:initializeProviders " + err.Error())
				return nil, err
			}

			// Store in maps for reuse
			crowdsecComponents[groupingKey] = crowdsecComponent
			cacheClients[groupingKey] = cacheClient
		}
	}

	bouncer := &Bouncer{
		next:     next,
		name:     name,
		template: template.New("CrowdsecBouncer").Delims("[[", "]]"),

		enabled:                 config.Enabled,
		crowdsecMode:            config.CrowdsecMode,
		remediationCustomHeader: config.RemediationHeadersCustomName,
		forwardedCustomHeader:   config.ForwardedHeadersCustomName,
		countryHeader:           config.CountryHeader,
		asnHeader:               config.ASNHeader,
		remediationStatusCode:   config.RemediationStatusCode,
		banTemplateString:       banTemplateString,
		log:                     log,
		crowdsecComponent:       crowdsecComponent,
		serverPoolStrategy: &ip.PoolStrategy{
			Checker: serverChecker,
		},
		clientPoolStrategy: &ip.PoolStrategy{
			Checker: clientChecker,
		},
		captchaClient: &captcha.Client{},
	}
	// Initialize captcha client if not in appsec-only mode
	if config.CrowdsecMode != configuration.AppsecMode {

		config.CaptchaSiteKey, _ = configuration.GetVariable(config, "CaptchaSiteKey")
		config.CaptchaSecretKey, _ = configuration.GetVariable(config, "CaptchaSecretKey")
		err = bouncer.captchaClient.New(
			log,
			cacheClients[groupingKey],
			&http.Client{
				Transport: &http.Transport{MaxIdleConns: 10, IdleConnTimeout: 30 * time.Second},
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
			config.CaptchaHTMLFilePath,
			config.CaptchaGracePeriodSeconds,
		)
		if err != nil {
			log.Error("CaptchaClient not valid " + err.Error())
			return nil, err
		}
	}

	bouncer.log.Debug("New initialized mode:" + config.CrowdsecMode)

	return bouncer, nil
}

// ServeHTTP principal function of plugin.
//
//nolint:nestif,gocyclo
func (bouncer *Bouncer) ServeHTTP(rw http.ResponseWriter, req *http.Request) {

	// Per bouncer configuration supported
	if !bouncer.enabled {
		bouncer.next.ServeHTTP(rw, req)
		return
	}

	// Here we check for the trusted IPs in the forwardedCustomHeader
	remoteIP, err := ip.GetRemoteIP(req, bouncer.serverPoolStrategy, bouncer.forwardedCustomHeader)
	if err != nil {
		bouncer.log.Error(fmt.Sprintf("ServeHTTP:getRemoteIp ip:%s %s", remoteIP, err.Error()))
		handleBanServeHTTP(bouncer, rw)
		return
	}
	isTrusted, err := bouncer.clientPoolStrategy.Checker.Contains(remoteIP)
	if err != nil {
		bouncer.log.Error(fmt.Sprintf("ServeHTTP:checkerContains ip:%s %s", remoteIP, err.Error()))
		handleBanServeHTTP(bouncer, rw)
		return
	}

	// if our IP is in the trusted list we bypass the next checks
	bouncer.log.Debug(fmt.Sprintf("ServeHTTP ip:%s isTrusted:%v", remoteIP, isTrusted))
	if isTrusted {
		bouncer.next.ServeHTTP(rw, req)
		return
	}

	// Use CrowdSec component for all decision checking (handles all modes internally)
	// Create decision request
	decisionReq := &decision.DecisionRequest{
		IP:       net.ParseIP(remoteIP),
		IPString: remoteIP,
		Mode:     bouncer.crowdsecMode,
		HTTPReq:  req,
	}

	// Extract country from header if configured
	if bouncer.countryHeader != "" {
		decisionReq.Country = req.Header.Get(bouncer.countryHeader)
	}

	// Extract ASN from header if configured
	if bouncer.asnHeader != "" {
		decisionReq.ASN = req.Header.Get(bouncer.asnHeader)
	}

	// Check for decisions (handles all modes: none, live, stream, alone internally)
	result, err := bouncer.crowdsecComponent.CheckDecision(decisionReq)
	if err != nil {
		bouncer.log.Error(fmt.Sprintf("ServeHTTP:CheckDecision ip:%s %s", remoteIP, err.Error()))
		handleBanServeHTTP(bouncer, rw)
		return
	}

	if result.Blocked {
		bouncer.log.Debug(fmt.Sprintf("ServeHTTP ip:%s blocked by %s decision:%s scenario:%s",
			remoteIP, result.MatchedBy, result.Type, result.Scenario))
		handleRemediationServeHTTP(bouncer, remoteIP, string(result.Type), rw, req)
		return
	}

	// Allow request if no blocking decision found
	handleNextServeHTTP(bouncer, remoteIP, rw, req)
}

// Legacy types removed - now in pkg/types and pkg/crowdsecclient

// To append Headers we need to call rw.WriteHeader after set any header.
func handleBanServeHTTP(bouncer *Bouncer, rw http.ResponseWriter) {
	if bouncer.remediationCustomHeader != "" {
		rw.Header().Set(bouncer.remediationCustomHeader, "ban")
	}
	if bouncer.banTemplateString == "" {
		rw.WriteHeader(bouncer.remediationStatusCode)
		return
	}
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	rw.WriteHeader(bouncer.remediationStatusCode)
	_, err := fmt.Fprint(rw, bouncer.banTemplateString)
	if err != nil {
		bouncer.log.Error("handleBanServeHTTP could not write template to ResponseWriter")
	}
}

func handleRemediationServeHTTP(bouncer *Bouncer, remoteIP, remediation string, rw http.ResponseWriter, req *http.Request) {
	bouncer.log.Debug(fmt.Sprintf("handleRemediationServeHTTP ip:%s remediation:%s", remoteIP, remediation))
	if bouncer.captchaClient.Valid && (remediation == cache.CaptchaValue || remediation == "captcha") {
		if bouncer.captchaClient.Check(remoteIP) {
			handleNextServeHTTP(bouncer, remoteIP, rw, req)
			return
		}
		// Captcha serving - metrics handled by CrowdSec component
		bouncer.captchaClient.ServeHTTP(rw, req, remoteIP)
		return
	}
	handleBanServeHTTP(bouncer, rw)
}

func handleNextServeHTTP(bouncer *Bouncer, remoteIP string, rw http.ResponseWriter, req *http.Request) {
	// AppSec is now handled by the CrowdSec component
	// TODO: Not sure if we should separate appsec from crowdsec component, or simply treat is as a decision provider.
	bouncer.next.ServeHTTP(rw, req)
}

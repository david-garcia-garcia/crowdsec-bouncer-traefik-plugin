// Package crowdsec_bouncer_traefik_plugin implements a middleware that communicates with crowdsec.
package crowdsec_bouncer_traefik_plugin //nolint:revive,stylecheck

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/appsec"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/bouncer"
	configuration "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/lapi"
	logger "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

// CreateConfig creates the default plugin configuration.
func CreateConfig() *configuration.Config {
	return configuration.New()
}

// New is the Traefik Yaegi constructor. It reclaims LAPI and AppSec backends and returns a per-router Bouncer.
// Stream/alone: one LAPI client per LAPI URL+key (CrowdSec one stream cursor per
// hashed key + outbound IP). Live/none: reclaim by LAPI identity. AppSec: reclaim by listener URL+key.
func New(ctx context.Context, next http.Handler, config *configuration.Config, name string) (http.Handler, error) {
	config.LogLevel = strings.ToUpper(config.LogLevel)
	log := logger.NewWithFormat(config.LogLevel, config.LogFilePath, config.LogFormat)

	if config.BanFilePath == "" && config.BanHTMLFilePath != "" {
		config.BanFilePath = config.BanHTMLFilePath
	}
	if config.CaptchaHTMLFilePath != "" {
		config.CaptchaFilePath = config.CaptchaHTMLFilePath
	}

	if validateErr := configuration.ValidateParams(config, log); validateErr != nil {
		log.Error("New:validateParams " + validateErr.Error())
		return nil, validateErr
	}

	if config.CrowdsecMode == configuration.AppsecMode && !config.CrowdsecAppsecEnabled {
		return nil, fmt.Errorf("crowdsecMode appsec requires crowdsecAppsecEnabled")
	}

	if prepErr := lapi.Prepare(config, log); prepErr != nil {
		return nil, prepErr
	}
	if prepErr := appsec.Prepare(config, log); prepErr != nil {
		return nil, prepErr
	}

	bindCtx, cancelBind := context.WithCancel(ctx)
	failed := false
	defer func() {
		if failed {
			cancelBind()
		}
	}()

	var lapiClient *lapi.Client
	// Stream and alone poll GET /v1/decisions/stream. CrowdSec stores that
	// cursor on the bouncer row selected by hashed X-Api-Key plus the IP LAPI
	// sees (this process’s outbound address), not per middleware and not per
	// metrics interval. OpenStream keeps one ticker per URL+key in this process.
	if config.CrowdsecMode == configuration.StreamMode || config.CrowdsecMode == configuration.AloneMode {
		var streamErr error
		lapiClient, streamErr = lapi.OpenStream(bindCtx, config, log, name, pluginVersion)
		if streamErr != nil {
			failed = true
			return nil, streamErr
		}
	} else if config.CrowdsecMode != configuration.AppsecMode {
		// Live/none do not use stream_cursor. Two Clients on one key
		// stay valid (?ip= lookups). Reclaim by LAPI identity, including intervals.
		var openErr error
		lapiClient, openErr = lapi.OpenLive(bindCtx, config, log, name, pluginVersion)
		if openErr != nil {
			failed = true
			return nil, openErr
		}
	}

	var appsecClient *appsec.Client
	if config.CrowdsecAppsecEnabled {
		var appsecErr error
		appsecClient, appsecErr = appsec.Open(bindCtx, config, log, name, pluginVersion)
		if appsecErr != nil {
			failed = true
			return nil, appsecErr
		}
	}
	handler, bouncerErr := bouncer.New(next, name, config, lapiClient, appsecClient, log)
	if bouncerErr != nil {
		failed = true
		return nil, bouncerErr
	}
	return handler, nil
}

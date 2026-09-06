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
//
//nolint:nonamedreturns // defer rollback reads named err; Yaegi mishandles closure-captured bool in defer.
func New(ctx context.Context, next http.Handler, config *configuration.Config, name string) (handler http.Handler, err error) {
	config.LogLevel = strings.ToUpper(config.LogLevel)
	log := logger.NewWithFormat(config.LogLevel, config.LogFilePath, config.LogFormat)

	if config.BanFilePath == "" && config.BanHTMLFilePath != "" {
		config.BanFilePath = config.BanHTMLFilePath
	}
	if config.CaptchaHTMLFilePath != "" {
		config.CaptchaFilePath = config.CaptchaHTMLFilePath
	}

	if err = configuration.ValidateParams(config, log); err != nil {
		log.Error("New:validateParams " + err.Error())
		return nil, err
	}

	if config.CrowdsecMode == configuration.AppsecMode && !config.CrowdsecAppsecEnabled {
		return nil, fmt.Errorf("crowdsecMode appsec requires crowdsecAppsecEnabled")
	}

	if err = lapi.Prepare(config, log); err != nil {
		return nil, err
	}
	if err = appsec.Prepare(config, log); err != nil {
		return nil, err
	}

	bindCtx, cancelBind := context.WithCancel(ctx)
	defer func() {
		if err != nil {
			cancelBind()
		}
	}()

	var lapiClient *lapi.Client
	// Stream and alone poll GET /v1/decisions/stream. CrowdSec stores that
	// cursor on the bouncer row selected by hashed X-Api-Key plus the IP LAPI
	// sees (this process’s outbound address), not per middleware and not per
	// metrics interval. OpenStream keeps one ticker per URL+key in this process.
	if config.CrowdsecMode == configuration.StreamMode || config.CrowdsecMode == configuration.AloneMode {
		lapiClient, err = lapi.OpenStream(bindCtx, config, log, name, pluginVersion)
		if err != nil {
			return nil, err
		}
	} else if config.CrowdsecMode != configuration.AppsecMode {
		// Live/none do not use stream_cursor. Two Clients on one key
		// stay valid (?ip= lookups). Reclaim by LAPI identity, including intervals.
		lapiClient, err = lapi.OpenLive(bindCtx, config, log, name, pluginVersion)
		if err != nil {
			return nil, err
		}
	}

	var appsecClient *appsec.Client
	if config.CrowdsecAppsecEnabled {
		appsecClient, err = appsec.Open(bindCtx, config, log, name, pluginVersion)
		if err != nil {
			return nil, err
		}
	}
	return bouncer.New(next, name, config, lapiClient, appsecClient, log)
}

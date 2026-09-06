// Package crowdsec_bouncer_traefik_plugin implements a middleware that communicates with crowdsec.
package crowdsec_bouncer_traefik_plugin //nolint:revive,stylecheck

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/bouncer"
	configuration "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/crowdsecconnection"
	logger "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/reclaim"
)

// CreateConfig creates the default plugin configuration.
func CreateConfig() *configuration.Config {
	return configuration.New()
}

// New is the Traefik Yaegi constructor. It reclaims a CrowdsecConnection and returns a per-router Bouncer.
// Stream/alone: one connection per LAPI URL+key (CrowdSec one stream cursor per
// hashed key + outbound IP). Live/none/appsec: reclaim by full connection identity.
func New(ctx context.Context, next http.Handler, config *configuration.Config, name string) (http.Handler, error) {
	config.LogLevel = strings.ToUpper(config.LogLevel)
	log := logger.NewWithFormat(config.LogLevel, config.LogFilePath, config.LogFormat)

	if config.BanFilePath == "" && config.BanHTMLFilePath != "" {
		config.BanFilePath = config.BanHTMLFilePath
	}
	if config.CaptchaHTMLFilePath != "" {
		config.CaptchaFilePath = config.CaptchaHTMLFilePath
	}

	err := configuration.ValidateParams(config, log)
	if err != nil {
		log.Error("New:validateParams " + err.Error())
		return nil, err
	}

	prepErr := crowdsecconnection.Prepare(config, log)
	if prepErr != nil {
		return nil, prepErr
	}

	// Stream and alone poll GET /v1/decisions/stream. CrowdSec stores that
	// cursor on the bouncer row selected by hashed X-Api-Key plus the IP LAPI
	// sees (this process’s outbound address), not per middleware and not per
	// metrics interval. OpenStream keeps one ticker per URL+key in this process.
	if config.CrowdsecMode == configuration.StreamMode || config.CrowdsecMode == configuration.AloneMode {
		conn, streamErr := crowdsecconnection.OpenStream(ctx, config, log, name, pluginVersion)
		if streamErr != nil {
			return nil, streamErr
		}
		return bouncer.New(next, name, config, conn, log)
	}

	// Live/none/appsec do not use stream_cursor. Two Connections on one key
	// stay valid (?ip= lookups). Reclaim by full identity, including intervals.
	stored, openErr := reclaim.Open(ctx, crowdsecconnection.Key(config), log, func() (any, error) {
		return crowdsecconnection.New(config, log, pluginVersion)
	})
	if openErr != nil {
		return nil, openErr
	}
	conn, ok := stored.(*crowdsecconnection.CrowdsecConnection)
	if !ok {
		return nil, fmt.Errorf("%s: reclaim: want *crowdsecconnection.CrowdsecConnection, got %T", name, stored)
	}
	return bouncer.New(next, name, config, conn, log)
}

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

	stored, err := reclaim.Open(ctx, crowdsecconnection.Key(config), log, func() (any, error) {
		return crowdsecconnection.New(config, log)
	})
	if err != nil {
		return nil, err
	}
	conn, ok := stored.(*crowdsecconnection.CrowdsecConnection)
	if !ok {
		return nil, fmt.Errorf("%s: reclaim: want *crowdsecconnection.CrowdsecConnection, got %T", name, stored)
	}
	return bouncer.New(next, name, config, conn, log)
}

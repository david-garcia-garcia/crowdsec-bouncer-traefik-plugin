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
	// Snapshot Traefik's Config so Yaegi's pointer is not rewritten.
	prepared := *config
	prepared.LogLevel = strings.ToUpper(prepared.LogLevel)
	log := logger.NewWithFormat(prepared.LogLevel, prepared.LogFilePath, prepared.LogFormat)

	// Deprecated HTML path aliases apply on the snapshot only.
	if prepared.BanFilePath == "" && prepared.BanHTMLFilePath != "" {
		prepared.BanFilePath = prepared.BanHTMLFilePath
	}
	if prepared.CaptchaHTMLFilePath != "" {
		prepared.CaptchaFilePath = prepared.CaptchaHTMLFilePath
	}

	err := configuration.ValidateParams(&prepared, log)
	if err != nil {
		log.Error("New:validateParams " + err.Error())
		return nil, err
	}

	// Inline secrets and rewrite CAPI routing on the snapshot.
	prepErr := crowdsecconnection.Prepare(&prepared, log)
	if prepErr != nil {
		return nil, prepErr
	}

	// Reclaim the Crowdsec backend by identity of the prepared snapshot.
	stored, err := reclaim.Open(ctx, crowdsecconnection.Key(&prepared), log, func() (any, error) {
		return crowdsecconnection.New(&prepared, log, pluginVersion)
	})
	if err != nil {
		return nil, err
	}
	conn, ok := stored.(*crowdsecconnection.CrowdsecConnection)
	if !ok {
		return nil, fmt.Errorf("%s: reclaim: want *crowdsecconnection.CrowdsecConnection, got %T", name, stored)
	}
	return bouncer.New(next, name, &prepared, conn, log)
}

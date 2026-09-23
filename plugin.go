// Package crowdsec_bouncer_traefik_plugin is the Traefik Yaegi entry (CreateConfig / New).
//
// Each New is one middleware. Per leg (LAPI, AppSec) it may own a Client, bounce
// against a named instance, both, or neither.
//
//	Open:          reclaim holder. Keeps that Client alive (stream ticker, HTTP).
//	               Last holder gone → Sleep, then Close after table grace.
//	ClearPublisher: this Traefik name no longer owns the leg; drop its aliases
//	               so watchers unbind. Do not Clear a still-owned reconstruct
//	               or subscribers flash empty before SetAlias.
//	SetAlias:      publish the instance name to the Client just Opened.
//	               Exclusive: a second publisher fails New.
//	Watch:         subscriber. Copies the current Client (or typed nil) into
//	               the Bouncer's atomic.Value. Not a holder — does not keep
//	               the Client alive and does not Close it.
//	Unwatch:       drop that subscriber when Traefik cancels this New's ctx.
//	               The backend stays up if another holder still Opened it.
package crowdsec_bouncer_traefik_plugin //nolint:revive,stylecheck

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/appsec"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/bouncer"
	configuration "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/lapi"
	logger "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/reclaim"
)

const (
	legLAPI   = "lapi"
	legAppSec = "appsec"
)

// instanceAlias is this plugin's opaque reclaim name for one published slot.
// Reclaim never parses it; SetAlias/ClearPublisher use group for rename and clear.
func instanceAlias(leg, instanceName string) string {
	if instanceName == "" {
		return ""
	}
	return "alias:" + leg + ":" + instanceName
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *configuration.Config {
	return configuration.New()
}

// New snapshots Traefik's config, Opens owned legs, publishes their instance names,
// and returns a Bouncer that ServeHTTP-Loads those names via Watch.
//
// crowdsecLapiEnabled / crowdsecAppsecEnabled = own (Open + SetAlias).
// enabled + a non-empty instance name = bounce (Watch). Those axes are independent.
//
// Open binds bindCtx, a child of Traefik's constructor ctx. The table has no Release:
// cancel bindCtx on a failed New so a half-built constructor does not leave a stream
// polling for the process lifetime. Success leaves bindCtx live; Traefik cancel of
// ctx still ends the holders.
func New(ctx context.Context, next http.Handler, rawConfig *configuration.Config, name string) (handler http.Handler, err error) {
	// Shallow copy: Config's []string and map[string]string fields still alias the caller's.
	config := *rawConfig
	config.LogLevel = strings.ToUpper(config.LogLevel)
	log := logger.NewWithFormat(config.LogLevel, config.LogFilePath, config.LogFormat)

	if err = configuration.ValidateParams(&config, log); err != nil {
		log.Error("New:validateParams", "error", err)
		return nil, err
	}
	// TODO: this has to go. Table grace is process-global (first New wins), not per slot.
	// E2e needed reclaimGraceSeconds=2 instead of ProcessGrace 30s so dispose is not the
	// production wait. Revisit when grace can be per incarnation or tests do not need this knob.
	reclaim.EnsureProcessGrace(time.Duration(config.ReclaimGraceSeconds) * time.Second)

	// Secrets plus omitted instance name → Traefik name, only when that leg is owned.
	if err = lapi.Prepare(&config, log, name); err != nil {
		return nil, err
	}
	if err = appsec.Prepare(&config, log, name); err != nil {
		return nil, err
	}

	// Holder lease for everything this New Opens. Cancel only on error (named err).
	bindCtx, releaseHolders := context.WithCancel(ctx)
	defer func() {
		if err != nil {
			releaseHolders()
		}
	}()

	if err = openOwned(bindCtx, &config, log, name); err != nil {
		return nil, err
	}
	if err = claimOwned(&config, log, name); err != nil {
		return nil, err
	}

	// Bounce: the router is on and an instance name is set. Owning is a different flag.
	subscribeLAPI := config.Enabled && config.CrowdsecLapiInstanceName != ""
	subscribeAppSec := config.Enabled && config.CrowdsecAppsecInstanceName != ""
	route, err := bouncer.New(next, name, &config, subscribeLAPI, subscribeAppSec, log)
	if err != nil {
		return nil, err
	}
	if subscribeLAPI {
		watchBinding(legLAPI, config.CrowdsecLapiInstanceName, name, route.LAPIBinding(), (*lapi.Client)(nil), log, config.DecisionScopeHeaders)
	}
	if subscribeAppSec {
		watchBinding(legAppSec, config.CrowdsecAppsecInstanceName, name, route.AppSecBinding(), (*appsec.Client)(nil), log, nil)
	}
	// Traefik cancel of this middleware: drop our Watchers, not the Opened Clients.
	context.AfterFunc(ctx, func() {
		if subscribeLAPI {
			reclaim.Unwatch(instanceAlias(legLAPI, config.CrowdsecLapiInstanceName), route.LAPIBinding())
		}
		if subscribeAppSec {
			reclaim.Unwatch(instanceAlias(legAppSec, config.CrowdsecAppsecInstanceName), route.AppSecBinding())
		}
	})
	return route, nil
}

// openOwned is the own axis: Open each enabled leg on bindCtx, or ClearPublisher when
// this reconstruct dropped that flag (leftover alias would keep subscribers bound).
func openOwned(bindCtx context.Context, config *configuration.Config, log *slog.Logger, name string) error {
	if err := openOwnedLeg(bindCtx, config, log, name, config.CrowdsecLapiEnabled, legLAPI); err != nil {
		return err
	}
	return openOwnedLeg(bindCtx, config, log, name, config.CrowdsecAppsecEnabled, legAppSec)
}

func openOwnedLeg(bindCtx context.Context, config *configuration.Config, log *slog.Logger, name string, enabled bool, group string) error {
	if !enabled {
		reclaim.ClearPublisher(name, group)
		return nil
	}
	switch group {
	case legLAPI:
		if config.CrowdsecMode == configuration.StreamMode || config.CrowdsecMode == configuration.AloneMode {
			_, err := lapi.OpenStream(bindCtx, config, log, name, pluginVersion)
			return err
		}
		_, err := lapi.OpenLive(bindCtx, config, log, name, pluginVersion)
		return err
	case legAppSec:
		_, err := appsec.Open(bindCtx, config, log, name, pluginVersion)
		return err
	}
	return nil
}

// claimOwned publishes each owned instance name (SetAlias) to the Client Open just
// created. A taken name fails New. If AppSec's claim fails after LAPI published,
// drop the LAPI alias so we do not leave a half-claimed owner.
func claimOwned(config *configuration.Config, log *slog.Logger, name string) error {
	if err := claimOwnedLeg(config, log, name, config.CrowdsecLapiEnabled, legLAPI); err != nil {
		return err
	}
	err := claimOwnedLeg(config, log, name, config.CrowdsecAppsecEnabled, legAppSec)
	if err != nil && config.CrowdsecLapiEnabled {
		reclaim.ClearPublisher(name, legLAPI)
	}
	return err
}

func claimOwnedLeg(config *configuration.Config, log *slog.Logger, name string, enabled bool, group string) error {
	if !enabled {
		return nil
	}
	switch group {
	case legLAPI:
		return claimAlias(lapi.OwnershipKey(config, name), group, config.CrowdsecLapiInstanceName, name, log)
	case legAppSec:
		return claimAlias(appsec.Key(config, name), group, config.CrowdsecAppsecInstanceName, name, log)
	}
	return nil
}

func claimAlias(key, group, instanceName, publisher string, log *slog.Logger) error {
	err := reclaim.SetAlias(key, instanceAlias(group, instanceName), publisher, group)
	if err != nil {
		log.Error("crowdsec instance name taken", "leg", group, "instanceName", instanceName, "rejected", publisher)
	}
	return err
}

// watchBinding is the bounce axis: attach dest to that instance name. ServeHTTP Loads
// dest; this call only Stores the current value (or typed empty) and logs once.
func watchBinding(leg, instanceName, traefikName string, dest *atomic.Value, empty any, log *slog.Logger, headerScopes map[string]string) {
	reclaim.Watch(instanceAlias(leg, instanceName), dest, empty)
	current := reclaim.Unbox(dest)
	incarnation := incarnationOf(current)
	if incarnation == "" {
		log.Debug("crowdsec bouncer unbound", "traefikName", traefikName, "leg", leg, "instanceName", instanceName)
		return
	}
	if client, ok := current.(*lapi.Client); ok {
		missing := decisionscope.MissingStreamScopes(headerScopes, client.StreamScopes())
		if len(missing) > 0 {
			log.Warn("crowdsec bouncer stream scopes missing",
				"traefikName", traefikName,
				"missing", strings.Join(missing, ","),
			)
		}
	}
	log.Info("crowdsec bouncer bound", "traefikName", traefikName, "leg", leg, "instanceName", instanceName, "incarnation", incarnation)
}

func incarnationOf(current any) string {
	switch client := current.(type) {
	case *lapi.Client:
		return client.Incarnation()
	case *appsec.Client:
		return client.Incarnation()
	default:
		return ""
	}
}

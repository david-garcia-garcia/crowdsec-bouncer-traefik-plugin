// Package crowdsec_bouncer_traefik_plugin implements a middleware that communicates with crowdsec.
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
	legLAPI         = "lapi"
	legAppSec       = "appsec"
	aliasPrefixLAPI = "alias:lapi:"
	aliasPrefixWAF  = "alias:appsec:"
	msgTaken        = "crowdsec instance name taken"
	msgBound        = "crowdsec bouncer bound"
	msgUnbound      = "crowdsec bouncer unbound"
)

// CreateConfig creates the default plugin configuration.
func CreateConfig() *configuration.Config {
	return configuration.New()
}

// New is the Traefik Yaegi constructor. It opens owned LAPI/AppSec legs, publishes
// named aliases on the reclaim table, and returns a per-router Bouncer that late-binds
// via atomic.Value.
//
// New works on a snapshot of the config Traefik owns, and binds every reclaim Open to a
// child of the constructor ctx, so a constructor that fails partway releases what it opened.
func New(ctx context.Context, next http.Handler, config *configuration.Config, name string) (handler http.Handler, err error) {
	// Shallow copy: Config's []string and map[string]string fields still alias the caller's.
	prepared := *config
	prepared.LogLevel = strings.ToUpper(prepared.LogLevel)
	log := logger.NewWithFormat(prepared.LogLevel, prepared.LogFilePath, prepared.LogFormat)

	if err = configuration.ValidateParams(&prepared, log); err != nil {
		log.Error("New:validateParams", "error", err)
		return nil, err
	}
	reclaim.EnsureProcessGrace(time.Duration(prepared.ReclaimGraceSeconds) * time.Second)

	if err = lapi.Prepare(&prepared, log); err != nil {
		return nil, err
	}
	if err = appsec.Prepare(&prepared, log); err != nil {
		return nil, err
	}
	configuration.PrepopulateInstanceNames(&prepared, name)

	bindCtx, releaseHolders := context.WithCancel(ctx)
	defer func() {
		if err != nil {
			releaseHolders()
		}
	}()

	if err = openAndAliasOwned(bindCtx, &prepared, log, name); err != nil {
		return nil, err
	}

	subscribeLAPI := prepared.Enabled && prepared.CrowdsecLapiInstanceName != ""
	subscribeAppSec := prepared.Enabled && prepared.CrowdsecAppsecInstanceName != ""
	route, err := bouncer.New(next, name, &prepared, subscribeLAPI, subscribeAppSec, log)
	if err != nil {
		return nil, err
	}
	handler = route
	if subscribeLAPI {
		watchAlias(legLAPI, prepared.CrowdsecLapiInstanceName, name, route.LAPIBinding(), (*lapi.Client)(nil), log, prepared.DecisionScopeHeaders)
	}
	if subscribeAppSec {
		watchAlias(legAppSec, prepared.CrowdsecAppsecInstanceName, name, route.AppSecBinding(), (*appsec.Client)(nil), log, nil)
	}
	context.AfterFunc(ctx, func() {
		if subscribeLAPI {
			reclaim.Unwatch(aliasKey(legLAPI, prepared.CrowdsecLapiInstanceName), route.LAPIBinding())
		}
		if subscribeAppSec {
			reclaim.Unwatch(aliasKey(legAppSec, prepared.CrowdsecAppsecInstanceName), route.AppSecBinding())
		}
	})
	return handler, err
}

type aliasClaim struct {
	alias     string
	publisher string
}

func openAndAliasOwned(bindCtx context.Context, prepared *configuration.Config, log *slog.Logger, name string) error {
	var claimed []aliasClaim
	if prepared.CrowdsecLapiEnabled {
		var err error
		if prepared.CrowdsecMode == configuration.StreamMode || prepared.CrowdsecMode == configuration.AloneMode {
			_, err = lapi.OpenStream(bindCtx, prepared, log, name, pluginVersion)
		} else {
			_, err = lapi.OpenLive(bindCtx, prepared, log, name, pluginVersion)
		}
		if err != nil {
			return err
		}
		if err = claimAlias(lapi.OwnershipKey(prepared, name), legLAPI, prepared.CrowdsecLapiInstanceName, name, (*lapi.Client)(nil), log); err != nil {
			return err
		}
		claimed = append(claimed, aliasClaim{alias: aliasKey(legLAPI, prepared.CrowdsecLapiInstanceName), publisher: name})
	} else {
		reclaim.ClearPublisher(name, aliasPrefixLAPI)
	}

	if prepared.CrowdsecAppsecEnabled {
		if _, err := appsec.Open(bindCtx, prepared, log, name, pluginVersion); err != nil {
			clearClaims(claimed)
			return err
		}
		if err := claimAlias(appsec.Key(prepared, name), legAppSec, prepared.CrowdsecAppsecInstanceName, name, (*appsec.Client)(nil), log); err != nil {
			clearClaims(claimed)
			return err
		}
	} else {
		reclaim.ClearPublisher(name, aliasPrefixWAF)
	}
	return nil
}

func claimAlias(key, leg, instanceName, publisher string, empty any, log *slog.Logger) error {
	if instanceName == "" {
		return nil
	}
	err := reclaim.SetAlias(key, aliasKey(leg, instanceName), publisher, empty)
	if err == nil {
		return nil
	}
	if log != nil {
		log.Error(msgTaken, "leg", leg, "instanceName", instanceName, "rejected", publisher)
	}
	return err
}

func clearClaims(claimed []aliasClaim) {
	for _, claim := range claimed {
		reclaim.ClearAlias(claim.alias, claim.publisher)
	}
}

func aliasKey(leg, instanceName string) string {
	return "alias:" + leg + ":" + instanceName
}

func watchAlias(leg, instanceName, traefikName string, dest *atomic.Value, empty any, log *slog.Logger, headerScopes map[string]string) {
	reclaim.Watch(aliasKey(leg, instanceName), reclaim.Watcher{
		Value: dest,
		Notify: func(current any, bound bool) {
			if log == nil {
				return
			}
			incarnation := incarnationOf(current)
			if !bound {
				log.Info(msgUnbound, "traefikName", traefikName, "leg", leg, "instanceName", instanceName, "incarnation", incarnation)
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
			log.Info(msgBound, "traefikName", traefikName, "leg", leg, "instanceName", instanceName, "incarnation", incarnation)
		},
	}, empty)
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

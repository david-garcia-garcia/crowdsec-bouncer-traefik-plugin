// Package crowdsec_bouncer_traefik_plugin is the Traefik Yaegi entry (CreateConfig / New).
//
// Each New is one middleware. Per leg (LAPI, AppSec, captcha) it may own a Client, bounce
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
//	valueChanged:  Watch's func(any). The any is reclaim.Published, whose Value
//	               is the client, or the typed empty when the alias is clear.
//	               The bouncer stores that into its own binding and validates it.
//	               Watch drops the subscriber when its ctx is done. The backend
//	               stays up if another holder still Opened it.
package crowdsec_bouncer_traefik_plugin //nolint:revive,stylecheck

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/appsec"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/bouncer"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/captcha"
	configuration "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/lapi"
	logger "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/reclaim"
)

const (
	legLAPI    = "lapi"
	legAppSec  = "appsec"
	legCaptcha = "captcha"
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
// lapiEnabled / appsecEnabled / captchaEnabled = own (Open + SetAlias).
// bouncerEnabled + a non-empty instance name = bounce (Watch). Those axes are independent.
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
	if err = captcha.Prepare(&config, log, name); err != nil {
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
	subscribeLAPI := config.BouncerEnabled && config.LapiInstanceName != ""
	subscribeAppSec := config.BouncerEnabled && config.AppsecInstanceName != ""
	subscribeCaptcha := config.BouncerEnabled && config.CaptchaInstanceName != ""
	route, err := bouncer.New(next, name, &config, subscribeLAPI, subscribeAppSec, subscribeCaptcha, log)
	if err != nil {
		return nil, err
	}
	if subscribeLAPI {
		reclaim.Watch(ctx, instanceAlias(legLAPI, config.LapiInstanceName), (*lapi.Client)(nil), route.ReceiveLAPI)
	}
	if subscribeAppSec {
		reclaim.Watch(ctx, instanceAlias(legAppSec, config.AppsecInstanceName), (*appsec.Client)(nil), route.ReceiveAppSec)
	}
	if subscribeCaptcha {
		reclaim.Watch(ctx, instanceAlias(legCaptcha, config.CaptchaInstanceName), (*captcha.Client)(nil), route.ReceiveCaptcha)
	}
	return route, nil
}

// openOwned is the own axis: Open each enabled leg on bindCtx, or ClearPublisher when
// this reconstruct dropped that flag (leftover alias would keep subscribers bound).
func openOwned(bindCtx context.Context, config *configuration.Config, log *slog.Logger, name string) error {
	if err := openOwnedLeg(bindCtx, config, log, name, config.LapiEnabled, legLAPI); err != nil {
		return err
	}
	if err := openOwnedLeg(bindCtx, config, log, name, config.AppsecEnabled, legAppSec); err != nil {
		return err
	}
	return openOwnedLeg(bindCtx, config, log, name, config.CaptchaEnabled, legCaptcha)
}

func openOwnedLeg(bindCtx context.Context, config *configuration.Config, log *slog.Logger, name string, enabled bool, group string) error {
	if !enabled {
		reclaim.ClearPublisher(name, group)
		return nil
	}
	switch group {
	case legLAPI:
		_, err := lapi.Open(bindCtx, config, log, name, pluginVersion)
		return err
	case legAppSec:
		_, err := appsec.Open(bindCtx, config, log, name, pluginVersion)
		return err
	case legCaptcha:
		_, err := captcha.Open(bindCtx, config, log, name, pluginVersion)
		return err
	}
	return nil
}

// claimOwned publishes each owned instance name (SetAlias) to the Client Open just
// created. A taken name fails New. A later claim failure clears already-published
// legs (LAPI and AppSec when captcha's SetAlias fails) so we do not leave a
// half-claimed owner.
func claimOwned(config *configuration.Config, log *slog.Logger, name string) error {
	if err := claimOwnedLeg(config, log, name, config.LapiEnabled, legLAPI); err != nil {
		return err
	}
	if err := claimOwnedLeg(config, log, name, config.AppsecEnabled, legAppSec); err != nil {
		if config.LapiEnabled {
			reclaim.ClearPublisher(name, legLAPI)
		}
		return err
	}
	err := claimOwnedLeg(config, log, name, config.CaptchaEnabled, legCaptcha)
	if err != nil {
		if config.LapiEnabled {
			reclaim.ClearPublisher(name, legLAPI)
		}
		if config.AppsecEnabled {
			reclaim.ClearPublisher(name, legAppSec)
		}
	}
	return err
}

func claimOwnedLeg(config *configuration.Config, log *slog.Logger, name string, enabled bool, group string) error {
	if !enabled {
		return nil
	}
	switch group {
	case legLAPI:
		return claimAlias(lapi.OwnershipKey(config, name), group, config.LapiInstanceName, name, log)
	case legAppSec:
		return claimAlias(appsec.Key(config, name), group, config.AppsecInstanceName, name, log)
	case legCaptcha:
		return claimAlias(captcha.OwnershipKey(config, name), group, config.CaptchaInstanceName, name, log)
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

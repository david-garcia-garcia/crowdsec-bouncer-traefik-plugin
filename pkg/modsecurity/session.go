package modsecurity

import (
	"context"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"log/slog"
	"strconv"
	"strings"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/reclaim"
)

const ownerKeyPrefix = "modsec:owner:"

// ownership is the ModSec Open-key payload: middleware name plus sidecar knobs.
// Slot name, bounce, failMode, LAPI, AppSec, and captcha stay off it.
type ownership struct {
	MiddlewareName                string   `json:"middlewareName"`
	URL                           string   `json:"url"`
	HTTPTimeoutSeconds            int64    `json:"httpTimeoutSeconds"`
	BodyLimit                     int64    `json:"bodyLimit"`
	DenyVerbsWithBody             []string `json:"denyVerbsWithBody"`
	UnhealthyBackOffPeriodSecs    int64    `json:"unhealthyBackOffPeriodSecs"`
	UnhealthyMaxBackOffPeriodSecs int64    `json:"unhealthyMaxBackOffPeriodSecs"`
	UnhealthyFailureThreshold     int64    `json:"unhealthyFailureThreshold"`
	UnhealthyFailureRatio         float64  `json:"unhealthyFailureRatio"`
}

func ownershipFrom(cfg *configuration.Config, middlewareName string) ownership {
	return ownership{
		MiddlewareName:                middlewareName,
		URL:                           cfg.ModsecURL,
		HTTPTimeoutSeconds:            cfg.ModsecHTTPTimeoutSeconds,
		BodyLimit:                     cfg.ModsecBodyLimit,
		DenyVerbsWithBody:             cfg.ModsecDenyVerbsWithBody,
		UnhealthyBackOffPeriodSecs:    cfg.ModsecUnhealthyBackOffPeriodSecs,
		UnhealthyMaxBackOffPeriodSecs: cfg.ModsecUnhealthyMaxBackOffPeriodSecs,
		UnhealthyFailureThreshold:     cfg.ModsecUnhealthyFailureThreshold,
		UnhealthyFailureRatio:         cfg.ModsecUnhealthyFailureRatio,
	}
}

func hashBytes(payload []byte) string {
	hasher := fnv.New64a()
	_, _ = hasher.Write(payload)
	return strconv.FormatUint(hasher.Sum64(), 16)
}

func hashJSON(value any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		return fmt.Sprint(value)
	}
	return hashBytes(encoded)
}

// OwnershipKey is the ModSec Client reclaim Open key: middleware name plus sidecar knobs.
func OwnershipKey(cfg *configuration.Config, middlewareName string) string {
	return ownerKeyPrefix + hashJSON(ownershipFrom(cfg, middlewareName))
}

// Prepare fills an omitted ModSec instance name with the Traefik name only when owned.
func Prepare(cfg *configuration.Config, _ *slog.Logger, traefikName string) error {
	if cfg.ModsecEnabled && strings.TrimSpace(cfg.ModsecInstanceName) == "" {
		cfg.ModsecInstanceName = traefikName
	}
	return nil
}

// Open reclaims a ModSec Client by middleware name plus sidecar knobs.
func Open(ctx context.Context, cfg *configuration.Config, log *slog.Logger, middlewareName, pluginVersion string) (*Client, error) {
	bindKey := OwnershipKey(cfg, middlewareName)
	stored, openErr := reclaim.OpenWithHooks(ctx, bindKey, log, func() (any, reclaim.Hooks, error) {
		client, err := New(cfg, log, pluginVersion, middlewareName, bindKey)
		if err != nil {
			return nil, reclaim.Hooks{}, err
		}
		return client, reclaim.Hooks{Sleep: client.Sleep, Wake: client.Wake, Close: client.Close}, nil
	})
	if openErr != nil {
		return nil, openErr
	}
	client, ok := stored.(*Client)
	if !ok {
		return nil, fmt.Errorf("%s: reclaim: want *modsecurity.Client, got %T", middlewareName, stored)
	}
	client.bindIdentity(middlewareName, bindKey)
	return client, nil
}

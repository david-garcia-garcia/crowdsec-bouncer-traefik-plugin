package appsec

import (
	"context"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"log/slog"
	"strconv"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/reclaim"
)

const keyPrefix = "appsec:"

// identity is the reclaim-key payload for one AppSec listener.
// HTTP timeout and AppSec TLS are omitted so a reload of those knobs
// reuses the Client. Per-router failure action is not included either.
type identity struct {
	Scheme    string `json:"scheme"`
	Host      string `json:"host"`
	Path      string `json:"path"`
	Key       string `json:"key"`
	BodyLimit int64  `json:"bodyLimit"`
}

func identityFrom(cfg *configuration.Config) identity {
	return identity{
		Scheme:    cfg.CrowdsecAppsecScheme,
		Host:      cfg.CrowdsecAppsecHost,
		Path:      cfg.CrowdsecAppsecPath,
		Key:       cfg.CrowdsecAppsecKey,
		BodyLimit: cfg.CrowdsecAppsecBodyLimit,
	}
}

func hashBytes(payload []byte) string {
	hasher := fnv.New64a()
	_, _ = hasher.Write(payload)
	return strconv.FormatUint(hasher.Sum64(), 16)
}

// IdentityHex is the hash suffix of Key.
func IdentityHex(cfg *configuration.Config) string {
	encoded, err := json.Marshal(identityFrom(cfg))
	if err != nil {
		return fmt.Sprint(cfg)
	}
	return hashBytes(encoded)
}

// Key is the process reclaim table key for one AppSec Client.
func Key(cfg *configuration.Config) string {
	return keyPrefix + IdentityHex(cfg)
}

// Open reclaims an AppSec Client by listener identity.
func Open(ctx context.Context, cfg *configuration.Config, log *slog.Logger, middlewareName, pluginVersion string) (*Client, error) {
	// OpenWithHooks + type assert: OpenTyped still takes func() (any, Hooks, error).
	stored, openErr := reclaim.OpenWithHooks(ctx, Key(cfg), log, func() (any, reclaim.Hooks, error) {
		client, err := New(cfg, log, pluginVersion)
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
		return nil, fmt.Errorf("%s: reclaim: want *appsec.Client, got %T", middlewareName, stored)
	}
	_, adoptErr := client.AdoptTransport(cfg)
	if adoptErr != nil {
		return nil, adoptErr
	}
	return client, nil
}

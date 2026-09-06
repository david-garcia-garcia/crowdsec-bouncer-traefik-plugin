package appsec

import (
	"context"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"log/slog"
	"strconv"

	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/reclaim"
)

const keyPrefix = "appsec:"

// identity is the reclaim-key payload for one AppSec listener.
type identity struct {
	Scheme                  string `json:"scheme"`
	Host                    string `json:"host"`
	Path                    string `json:"path"`
	Key                     string `json:"key"`
	BodyLimit               int64  `json:"bodyLimit"`
	HTTPTimeoutSeconds      int64  `json:"httpTimeoutSeconds"`
	TLSInsecureVerify       bool   `json:"tlsInsecureVerify"`
	TLSCertificateAuthority string `json:"tlsCa"`
	TLSCertificateBouncer   string `json:"tlsCert"`
}

func identityFrom(cfg *configuration.Config) identity {
	return identity{
		Scheme:                  cfg.CrowdsecAppsecScheme,
		Host:                    cfg.CrowdsecAppsecHost,
		Path:                    cfg.CrowdsecAppsecPath,
		Key:                     cfg.CrowdsecAppsecKey,
		BodyLimit:               cfg.CrowdsecAppsecBodyLimit,
		HTTPTimeoutSeconds:      cfg.HTTPTimeoutSeconds,
		TLSInsecureVerify:       cfg.CrowdsecAppsecTLSInsecureVerify,
		TLSCertificateAuthority: cfg.CrowdsecAppsecTLSCertificateAuthority,
		TLSCertificateBouncer:   cfg.CrowdsecAppsecTLSCertificateBouncer,
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
	stored, openErr := reclaim.OpenWithGrace(ctx, Key(cfg), log, ReclaimGraceDuration, func() (any, error) {
		client, err := New(cfg, log, pluginVersion)
		if err != nil {
			return nil, err
		}
		return &reclaim.Wrapped{Value: client, Sleep: client.Sleep, Wake: client.Wake, Close: client.Close}, nil
	})
	if openErr != nil {
		return nil, openErr
	}
	client, ok := stored.(*Client)
	if !ok {
		return nil, fmt.Errorf("%s: reclaim: want *appsec.Client, got %T", middlewareName, stored)
	}
	return client, nil
}

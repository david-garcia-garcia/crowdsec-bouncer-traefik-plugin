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

// identity is the reclaim-key payload for one AppSec Client: middleware name plus knobs.
type identity struct {
	MiddlewareName           string `json:"middlewareName"`
	Scheme                   string `json:"scheme"`
	Host                     string `json:"host"`
	Path                     string `json:"path"`
	Key                      string `json:"key"`
	BodyLimit                int64  `json:"bodyLimit"`
	TLSInsecureVerify        bool   `json:"tlsInsecureVerify"`
	TLSCertificateAuthority  string `json:"tlsCertificateAuthority"`
	TLSClientCertificate    string `json:"tlsClientCertificate"`
	TLSClientKey string `json:"tlsClientKey"`
	HTTPTimeoutSeconds       int64  `json:"httpTimeoutSeconds"`
}

func identityFrom(cfg *configuration.Config, middlewareName string) identity {
	ca, _ := configuration.GetVariable(cfg, "AppsecTLSCertificateAuthority")
	cert, _ := configuration.GetVariable(cfg, "AppsecTLSClientCertificate")
	certKey, _ := configuration.GetVariable(cfg, "AppsecTLSClientKey")
	return identity{
		MiddlewareName:           middlewareName,
		Scheme:                   cfg.AppsecScheme,
		Host:                     cfg.AppsecHost,
		Path:                     cfg.AppsecPath,
		Key:                      cfg.AppsecKey,
		BodyLimit:                cfg.AppsecBodyLimit,
		TLSInsecureVerify:        cfg.AppsecTLSInsecureVerify,
		TLSCertificateAuthority:  ca,
		TLSClientCertificate:    cert,
		TLSClientKey: certKey,
		HTTPTimeoutSeconds:       cfg.AppsecHTTPTimeoutSeconds,
	}
}

func hashBytes(payload []byte) string {
	hasher := fnv.New64a()
	_, _ = hasher.Write(payload)
	return strconv.FormatUint(hasher.Sum64(), 16)
}

// IdentityHex is the hash suffix of Key.
func IdentityHex(cfg *configuration.Config, middlewareName string) string {
	encoded, err := json.Marshal(identityFrom(cfg, middlewareName))
	if err != nil {
		return fmt.Sprint(cfg)
	}
	return hashBytes(encoded)
}

// Key is the process reclaim table key for one AppSec Client.
func Key(cfg *configuration.Config, middlewareName string) string {
	return keyPrefix + IdentityHex(cfg, middlewareName)
}

// Open reclaims an AppSec Client by middleware name plus listener knobs.
func Open(ctx context.Context, cfg *configuration.Config, log *slog.Logger, middlewareName, pluginVersion string) (*Client, error) {
	bindKey := Key(cfg, middlewareName)
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
		return nil, fmt.Errorf("%s: reclaim: want *appsec.Client, got %T", middlewareName, stored)
	}
	client.bindIdentity(middlewareName, bindKey)
	return client, nil
}

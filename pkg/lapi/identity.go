package lapi

import (
	"encoding/json"
	"fmt"
	"hash/fnv"
	"strconv"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
)

const keyPrefix = "lapi:"

// identity is the live/none remaining-fields payload hashed into Key and IdentityHex.
// MetricsUpdateIntervalSeconds stays so none/live routers that disagree get sibling
// Clients and each keeps its write-once metrics ticker. CAPI scenarios,
// updateMaxFailure, and UpdateIntervalSeconds stay omitted. Per-router policy,
// StreamStartupBlock, HTTP timeout, and LAPI TLS are omitted so a reload of
// those knobs reuses the Client. Ban/captcha templates, trusted IPs, Enabled,
// middleware name, log path, and decisionScopeHeaders are not included here
// either (stream scopes= is poller-owned; live passes scopes per LiveLookup).
type identity struct {
	Mode                         string   `json:"mode"`
	LapiScheme                   string   `json:"lapiScheme"`
	LapiHost                     string   `json:"lapiHost"`
	LapiPath                     string   `json:"lapiPath"`
	LapiKey                      string   `json:"lapiKey"`
	CapiMachineID                string   `json:"capiMachineId"`
	CapiPassword                 string   `json:"capiPassword"`
	RedisCacheEnabled            bool     `json:"redisCacheEnabled"`
	RedisCacheHost               string   `json:"redisCacheHost"`
	RedisCacheReadHosts          []string `json:"redisCacheReadHosts"`
	RedisCachePassword           string   `json:"redisCachePassword"`
	RedisCacheDatabase           string   `json:"redisCacheDatabase"`
	MetricsUpdateIntervalSeconds int64    `json:"metricsUpdateIntervalSeconds"`
}

// identityFrom maps configuration.Config into IdentityHex fields.
func identityFrom(cfg *configuration.Config) identity {
	return identity{
		Mode:                         cfg.CrowdsecMode,
		LapiScheme:                   cfg.CrowdsecLapiScheme,
		LapiHost:                     cfg.CrowdsecLapiHost,
		LapiPath:                     cfg.CrowdsecLapiPath,
		LapiKey:                      cfg.CrowdsecLapiKey,
		CapiMachineID:                cfg.CrowdsecCapiMachineID,
		CapiPassword:                 cfg.CrowdsecCapiPassword,
		RedisCacheEnabled:            cfg.RedisCacheEnabled,
		RedisCacheHost:               cfg.RedisCacheHost,
		RedisCacheReadHosts:          cfg.RedisCacheReadHosts,
		RedisCachePassword:           cfg.RedisCachePassword,
		RedisCacheDatabase:           cfg.RedisCacheDatabase,
		MetricsUpdateIntervalSeconds: cfg.MetricsUpdateIntervalSeconds,
	}
}

// hashBytes is FNV-64a hex used by IdentityHex and SessionHex.
func hashBytes(payload []byte) string {
	hasher := fnv.New64a()
	_, _ = hasher.Write(payload)
	return strconv.FormatUint(hasher.Sum64(), 16)
}

// IdentityHex is the exported hash of the live/none identity payload (not the Open suffix).
func IdentityHex(cfg *configuration.Config) string {
	b, err := json.Marshal(identityFrom(cfg))
	if err != nil {
		return fmt.Sprint(cfg)
	}
	return hashBytes(b)
}

// Key is the live/none Open key: SessionHex plus a hash of the identity payload
// (Redis store params and MetricsUpdateIntervalSeconds). Stream SessionKey and
// StoreKey still omit the metrics interval.
func Key(cfg *configuration.Config) string {
	return keyPrefix + SessionHex(cfg) + ":" + hashJSON(identityFrom(cfg))
}

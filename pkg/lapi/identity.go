package lapi

import (
	"encoding/json"
	"fmt"
	"hash/fnv"
	"strconv"

	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/configuration"
)

const keyPrefix = "lapi:"

// identity is the live/none reclaim-key payload (first-wins LAPI fields).
// Stream/alone use streamSession instead: LAPI URL+key only, so intervals
// cannot start a second GET /v1/decisions/stream poller on the same CrowdSec
// bouncer row. Per-router policy, StreamStartupBlock, HTTP timeout, and LAPI
// TLS are omitted so a reload of those knobs reuses the Client. Ban/captcha
// templates, trusted IPs, Enabled, middleware name, and log path are not
// included here either.
type identity struct {
	Mode                         string   `json:"mode"`
	LapiScheme                   string   `json:"lapiScheme"`
	LapiHost                     string   `json:"lapiHost"`
	LapiPath                     string   `json:"lapiPath"`
	LapiKey                      string   `json:"lapiKey"`
	CapiMachineID                string   `json:"capiMachineId"`
	CapiPassword                 string   `json:"capiPassword"`
	CapiScenarios                []string `json:"capiScenarios"`
	UpdateIntervalSeconds        int64    `json:"updateIntervalSeconds"`
	MetricsUpdateIntervalSeconds int64    `json:"metricsUpdateIntervalSeconds"`
	UpdateMaxFailure             int64    `json:"updateMaxFailure"`
	RedisCacheEnabled            bool     `json:"redisCacheEnabled"`
	RedisCacheHost               string   `json:"redisCacheHost"`
	RedisCacheReadHosts          []string `json:"redisCacheReadHosts"`
	RedisCachePassword           string   `json:"redisCachePassword"`
	RedisCacheDatabase           string   `json:"redisCacheDatabase"`
}

// identityFrom maps configuration.Config into reclaim identity fields.
func identityFrom(cfg *configuration.Config) identity {
	return identity{
		Mode:                         cfg.CrowdsecMode,
		LapiScheme:                   cfg.CrowdsecLapiScheme,
		LapiHost:                     cfg.CrowdsecLapiHost,
		LapiPath:                     cfg.CrowdsecLapiPath,
		LapiKey:                      cfg.CrowdsecLapiKey,
		CapiMachineID:                cfg.CrowdsecCapiMachineID,
		CapiPassword:                 cfg.CrowdsecCapiPassword,
		CapiScenarios:                cfg.CrowdsecCapiScenarios,
		UpdateIntervalSeconds:        cfg.UpdateIntervalSeconds,
		MetricsUpdateIntervalSeconds: cfg.MetricsUpdateIntervalSeconds,
		UpdateMaxFailure:             cfg.UpdateMaxFailure,
		RedisCacheEnabled:            cfg.RedisCacheEnabled,
		RedisCacheHost:               cfg.RedisCacheHost,
		RedisCacheReadHosts:          cfg.RedisCacheReadHosts,
		RedisCachePassword:           cfg.RedisCachePassword,
		RedisCacheDatabase:           cfg.RedisCacheDatabase,
	}
}

// hashBytes is FNV-64a hex used by IdentityHex and SessionHex.
func hashBytes(payload []byte) string {
	hasher := fnv.New64a()
	_, _ = hasher.Write(payload)
	return strconv.FormatUint(hasher.Sum64(), 16)
}

// IdentityHex is the Redis key prefix for live/none and the hash suffix of Key.
func IdentityHex(cfg *configuration.Config) string {
	b, err := json.Marshal(identityFrom(cfg))
	if err != nil {
		return fmt.Sprint(cfg)
	}
	return hashBytes(b)
}

// Key is the process reclaim table key for one Client.
func Key(cfg *configuration.Config) string {
	return keyPrefix + IdentityHex(cfg)
}

package lapi

import (
	"encoding/json"
	"fmt"
	"hash/fnv"
	"sort"
	"strconv"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
)

const keyPrefix = "lapi:"
const ownerKeyPrefix = "lapi:owner:"

// identity is the live/none remaining-fields payload hashed into IdentityHex.
// Middleware name, timeout, and TLS live on OwnershipKey, not here.
type identity struct {
	Mode                         string   `json:"mode"`
	Scheme                       string   `json:"scheme"`
	Host                         string   `json:"host"`
	Path                         string   `json:"path"`
	Key                          string   `json:"key"`
	CapiMachineID                string   `json:"capiMachineId"`
	CapiPassword                 string   `json:"capiPassword"`
	RedisEnabled                 bool     `json:"redisCacheEnabled"`
	RedisHost                    string   `json:"redisCacheHost"`
	RedisReadHosts               []string `json:"redisCacheReadHosts"`
	RedisPassword                string   `json:"redisCachePassword"`
	RedisDatabase                string   `json:"redisCacheDatabase"`
	MetricsUpdateIntervalSeconds int64    `json:"metricsUpdateIntervalSeconds"`
}

// ownership is the LAPI Open-key payload: middleware name plus client knobs.
type ownership struct {
	MiddlewareName               string   `json:"middlewareName"`
	Mode                         string   `json:"mode"`
	Scheme                       string   `json:"scheme"`
	Host                         string   `json:"host"`
	Path                         string   `json:"path"`
	Key                          string   `json:"key"`
	TLSInsecureVerify            bool     `json:"tlsInsecureVerify"`
	TLSCertificateAuthority      string   `json:"tlsCertificateAuthority"`
	TLSClientCertificate         string   `json:"tlsClientCertificate"`
	TLSClientKey                 string   `json:"tlsClientKey"`
	HTTPTimeoutSeconds           int64    `json:"httpTimeoutSeconds"`
	RedisEnabled                 bool     `json:"redisCacheEnabled"`
	RedisHost                    string   `json:"redisCacheHost"`
	RedisReadHosts               []string `json:"redisCacheReadHosts"`
	RedisPassword                string   `json:"redisCachePassword"`
	RedisDatabase                string   `json:"redisCacheDatabase"`
	StreamScopes                 []string `json:"streamScopes"`
	CapiMachineID                string   `json:"capiMachineId"`
	CapiPassword                 string   `json:"capiPassword"`
	UpdateIntervalSeconds        int64    `json:"updateIntervalSeconds"`
	MetricsUpdateIntervalSeconds int64    `json:"metricsUpdateIntervalSeconds"`
	UpdateMaxFailure             int64    `json:"updateMaxFailure"`
	CapiScenarios                []string `json:"capiScenarios"`
	DefaultDecisionSeconds       int64    `json:"defaultDecisionSeconds"`
}

func identityFrom(cfg *configuration.Config) identity {
	return identity{
		Mode:                         cfg.LapiMode,
		Scheme:                       cfg.LapiScheme,
		Host:                         cfg.LapiHost,
		Path:                         cfg.LapiPath,
		Key:                          cfg.LapiKey,
		CapiMachineID:                cfg.LapiCapiMachineID,
		CapiPassword:                 cfg.LapiCapiPassword,
		RedisEnabled:                 cfg.LapiRedisEnabled,
		RedisHost:                    cfg.LapiRedisHost,
		RedisReadHosts:               sortedCopy(cfg.LapiRedisReadHosts),
		RedisPassword:                cfg.LapiRedisPassword,
		RedisDatabase:                cfg.LapiRedisDatabase,
		MetricsUpdateIntervalSeconds: cfg.LapiMetricsUpdateIntervalSeconds,
	}
}

func ownershipFrom(cfg *configuration.Config, middlewareName string) ownership {
	ca, _ := configuration.GetVariable(cfg, "LapiTLSCertificateAuthority")
	cert, _ := configuration.GetVariable(cfg, "LapiTLSClientCertificate")
	certKey, _ := configuration.GetVariable(cfg, "LapiTLSClientKey")
	return ownership{
		MiddlewareName:               middlewareName,
		Mode:                         cfg.LapiMode,
		Scheme:                       cfg.LapiScheme,
		Host:                         cfg.LapiHost,
		Path:                         cfg.LapiPath,
		Key:                          cfg.LapiKey,
		TLSInsecureVerify:            cfg.LapiTLSInsecureVerify,
		TLSCertificateAuthority:      ca,
		TLSClientCertificate:         cert,
		TLSClientKey:                 certKey,
		HTTPTimeoutSeconds:           cfg.LapiHTTPTimeoutSeconds,
		RedisEnabled:                 cfg.LapiRedisEnabled,
		RedisHost:                    cfg.LapiRedisHost,
		RedisReadHosts:               sortedCopy(cfg.LapiRedisReadHosts),
		RedisPassword:                cfg.LapiRedisPassword,
		RedisDatabase:                cfg.LapiRedisDatabase,
		StreamScopes:                 decisionscope.CanonicalStreamScopes(cfg.LapiStreamScopes),
		CapiMachineID:                cfg.LapiCapiMachineID,
		CapiPassword:                 cfg.LapiCapiPassword,
		UpdateIntervalSeconds:        cfg.LapiUpdateIntervalSeconds,
		MetricsUpdateIntervalSeconds: cfg.LapiMetricsUpdateIntervalSeconds,
		UpdateMaxFailure:             cfg.LapiUpdateMaxFailure,
		CapiScenarios:                append([]string(nil), cfg.LapiCapiScenarios...),
		DefaultDecisionSeconds:       cfg.LapiDefaultDecisionSeconds,
	}
}

func sortedCopy(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := append([]string(nil), values...)
	sort.Strings(out)
	return out
}

func hashBytes(payload []byte) string {
	hasher := fnv.New64a()
	_, _ = hasher.Write(payload)
	return strconv.FormatUint(hasher.Sum64(), 16)
}

// IdentityHex is the exported hash of the live/none identity payload (not the Open suffix).
func IdentityHex(cfg *configuration.Config) string {
	encoded, err := json.Marshal(identityFrom(cfg))
	if err != nil {
		return fmt.Sprint(cfg)
	}
	return hashBytes(encoded)
}

// OwnershipKey is the LAPI Client reclaim Open key: middleware name plus client knobs.
func OwnershipKey(cfg *configuration.Config, middlewareName string) string {
	return ownerKeyPrefix + hashJSON(ownershipFrom(cfg, middlewareName))
}

// Key is the live/none Open key without middleware name (store-adjacent identity).
func Key(cfg *configuration.Config) string {
	return keyPrefix + SessionHex(cfg) + ":" + hashJSON(identityFrom(cfg))
}

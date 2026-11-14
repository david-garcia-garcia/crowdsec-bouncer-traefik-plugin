package lapi

import (
	"testing"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
)

// preKnobStreamSession is the streamSession payload as it was before lapiRemediationFallback existed.
type preKnobStreamSession struct {
	Mode                   string        `json:"mode"`
	Scheme                 string        `json:"scheme"`
	Host                   string        `json:"host"`
	Path                   string        `json:"path"`
	Key                    string        `json:"key"`
	CapiMachineID          string        `json:"capiMachineId"`
	CapiPassword           string        `json:"capiPassword"`
	DefaultDecisionSeconds int64         `json:"defaultDecisionSeconds"`
	StreamScopes           []string      `json:"streamScopes,omitempty"`
	Redis                  *sessionRedis `json:"redis,omitempty"`
}

// preKnobSessionHex hashes cfg the way SessionHex did before the knob, for upgrade comparisons.
func preKnobSessionHex(cfg *configuration.Config) string {
	return hashJSON(preKnobStreamSession{
		Mode:                   cfg.LapiMode,
		Scheme:                 cfg.LapiScheme,
		Host:                   cfg.LapiHost,
		Path:                   cfg.LapiPath,
		Key:                    cfg.LapiKey,
		CapiMachineID:          cfg.LapiCapiMachineID,
		CapiPassword:           cfg.LapiCapiPassword,
		DefaultDecisionSeconds: cfg.LapiDefaultDecisionSeconds,
		StreamScopes:           decisionscope.CanonicalStreamScopes(cfg.LapiStreamScopes),
	})
}

// TestSessionHex_DefaultRemediationFallbackKeepsPreKnobHash proves omitted and ban keep the upgrade hash.
func TestSessionHex_DefaultRemediationFallbackKeepsPreKnobHash(t *testing.T) {
	omitted := testStreamConfig("lapi.example:8080", 1)
	ban := testStreamConfig("lapi.example:8080", 1)
	ban.LapiRemediationFallback = configuration.LapiRemediationFallbackBan
	if SessionHex(omitted) != SessionHex(ban) {
		t.Fatal("omitted and ban lapiRemediationFallback must share SessionHex")
	}
	if SessionHex(omitted) != preKnobSessionHex(omitted) {
		t.Fatal("default lapiRemediationFallback must keep the SessionHex of a config that predates the knob")
	}
	if OwnershipKey(omitted, "mw") != OwnershipKey(ban, "mw") {
		t.Fatal("omitted and ban lapiRemediationFallback must share the ownership Open key")
	}
}

// TestSessionHex_RemediationFallbackChangeForksStoreAndClient proves a non-default value is a new store and Client.
func TestSessionHex_RemediationFallbackChangeForksStoreAndClient(t *testing.T) {
	ban := testStreamConfig("lapi.example:8080", 1)
	ban.LapiRemediationFallback = configuration.LapiRemediationFallbackBan
	for _, fallback := range []string{configuration.LapiRemediationFallbackIgnore, configuration.LapiRemediationFallbackCaptcha} {
		changed := testStreamConfig("lapi.example:8080", 1)
		changed.LapiRemediationFallback = fallback
		if SessionHex(ban) == SessionHex(changed) {
			t.Fatalf("ban to %s must fork SessionHex", fallback)
		}
		if OwnershipKey(ban, "mw") == OwnershipKey(changed, "mw") {
			t.Fatalf("ban to %s must change the ownership Open key", fallback)
		}
	}
}

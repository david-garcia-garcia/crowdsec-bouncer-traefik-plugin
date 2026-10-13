package bouncer

import (
	"testing"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/httprule"
)

func mustCompileActions(t *testing.T, rules []httprule.ActionRule) *httprule.ActionSet {
	t.Helper()
	set, err := httprule.NewActionSet(rules)
	if err != nil {
		t.Fatal(err)
	}
	return set
}

func mustPathAction(t *testing.T, name, path string, tokens ...string) *httprule.ActionSet {
	t.Helper()
	return mustCompileActions(t, []httprule.ActionRule{{Name: name, Action: tokens, Rule: httprule.Rule{Path: path}}})
}

func headerAction(name, header, pattern string, tokens ...string) httprule.ActionRule {
	return httprule.ActionRule{
		Name:   name,
		Action: tokens,
		Rule:   httprule.Rule{Headers: map[string]string{header: pattern}},
	}
}

func decisionHeaderRules() []httprule.ActionRule {
	return []httprule.ActionRule{
		headerAction("decision-ban", testForcedDecisionHeader, "^b$", httprule.ActionBan),
		headerAction("decision-captcha", testForcedDecisionHeader, "^c$", httprule.ActionCaptcha),
	}
}

func mustPathAndDecision(t *testing.T, name, path string, tokens ...string) *httprule.ActionSet {
	t.Helper()
	rules := append([]httprule.ActionRule{{Name: name, Action: tokens, Rule: httprule.Rule{Path: path}}}, decisionHeaderRules()...)
	return mustCompileActions(t, rules)
}

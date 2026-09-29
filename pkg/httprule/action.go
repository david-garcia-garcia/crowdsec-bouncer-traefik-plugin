package httprule

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// Action tokens on one ActionRule. Order in the authoring array does not matter.
const (
	ActionBan          = "ban"
	ActionBypass       = "bypass"
	ActionBypassAppsec = "bypassAppsec"
	ActionBypassLapi   = "bypassLapi"
	ActionCaptcha      = "captcha"
)

// ActionRule is one authoring row: unique name, action tokens, and Rule predicates.
// Traefik mapstructure squashes the embedded Rule so YAML stays flat with name and action.
type ActionRule struct {
	Action []string `json:"action,omitempty"`
	Name   string   `json:"name,omitempty"`
	Rule   `json:",inline"          mapstructure:",squash"`
}

// ActionSet is a compiled action list. Predicate match stays on Set; tokens stay beside it.
type ActionSet struct {
	names  []string
	set    *Set
	tokens []actionTokens
}

// actionTokens is the parsed action array for one compiled row.
type actionTokens struct {
	ban        bool
	captcha    bool
	skipAppsec bool
	skipLapi   bool
}

// NewActionSet validates names and action tokens, then compiles predicates with New.
// An empty list succeeds and matches nothing. Inner errors are index-prefixed rule %d.
func NewActionSet(rules []ActionRule) (*ActionSet, error) {
	extracted := make([]Rule, len(rules))
	names := make([]string, len(rules))
	tokens := make([]actionTokens, len(rules))
	seenNames := make(map[string]struct{}, len(rules))
	for i, rule := range rules {
		name, err := compileActionName(rule.Name, seenNames)
		if err != nil {
			return nil, fmt.Errorf("rule %d: %w", i, err)
		}
		parsed, err := compileActionTokens(rule.Action)
		if err != nil {
			return nil, fmt.Errorf("rule %d: %w", i, err)
		}
		names[i] = name
		tokens[i] = parsed
		extracted[i] = rule.Rule
		seenNames[name] = struct{}{}
	}
	set, err := New(extracted)
	if err != nil {
		return nil, err
	}
	return &ActionSet{names: names, set: set, tokens: tokens}, nil
}

// Matching returns every matching index in list order. Cookie is parsed once when needed.
func (set *ActionSet) Matching(httpReq *http.Request) []int {
	if set == nil || set.set == nil {
		return nil
	}
	return set.set.Matching(httpReq)
}

// Name is the authoring name at index i. Empty when the set is nil or i is out of range.
func (set *ActionSet) Name(i int) string {
	if set == nil || i < 0 || i >= len(set.names) {
		return ""
	}
	return set.names[i]
}

// Ban reports whether the row at index i has a ban token.
func (set *ActionSet) Ban(i int) bool {
	return set != nil && i >= 0 && i < len(set.tokens) && set.tokens[i].ban
}

// Captcha reports whether the row at index i has a captcha token.
func (set *ActionSet) Captcha(i int) bool {
	return set != nil && i >= 0 && i < len(set.tokens) && set.tokens[i].captcha
}

// SkipLapi reports whether the row at index i skips LAPI (bypass or bypassLapi).
func (set *ActionSet) SkipLapi(i int) bool {
	return set != nil && i >= 0 && i < len(set.tokens) && set.tokens[i].skipLapi
}

// SkipAppsec reports whether the row at index i skips AppSec (bypass or bypassAppsec).
func (set *ActionSet) SkipAppsec(i int) bool {
	return set != nil && i >= 0 && i < len(set.tokens) && set.tokens[i].skipAppsec
}

// compileActionName trims name, rejects empty, colon, and duplicates.
func compileActionName(raw string, seen map[string]struct{}) (string, error) {
	name := strings.TrimSpace(raw)
	if name == "" {
		return "", errors.New("name: empty")
	}
	if strings.Contains(name, ":") {
		return "", errors.New("name: contains colon")
	}
	if _, exists := seen[name]; exists {
		return "", errors.New("name: duplicate")
	}
	return name, nil
}

// compileActionTokens rejects empty, unknown, duplicate, and ban mixed with other tokens.
func compileActionTokens(raw []string) (actionTokens, error) {
	if len(raw) == 0 {
		return actionTokens{}, errors.New("action: empty")
	}
	seen := make(map[string]struct{}, len(raw))
	var parsed actionTokens
	for _, item := range raw {
		token := strings.TrimSpace(item)
		if token == "" {
			return actionTokens{}, errors.New("action: empty")
		}
		if _, exists := seen[token]; exists {
			return actionTokens{}, errors.New("action: duplicate")
		}
		seen[token] = struct{}{}
		switch token {
		case ActionBan:
			parsed.ban = true
		case ActionCaptcha:
			parsed.captcha = true
		case ActionBypass:
			parsed.skipLapi = true
			parsed.skipAppsec = true
		case ActionBypassLapi:
			parsed.skipLapi = true
		case ActionBypassAppsec:
			parsed.skipAppsec = true
		default:
			return actionTokens{}, fmt.Errorf("action: unknown %q", token)
		}
	}
	if parsed.ban && len(seen) > 1 {
		return actionTokens{}, errors.New("action: ban must be alone")
	}
	return parsed, nil
}

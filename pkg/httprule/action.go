package httprule

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// Action tokens on one ActionRule. Order in the authoring array does not matter.
// ActionBypass skips LAPI and AppSec; only ActionBypassRateLimit skips the rate limit.
const (
	ActionBan             = "ban"
	ActionBypass          = "bypass"
	ActionBypassAppsec    = "bypassAppsec"
	ActionBypassCaptcha   = "bypassCaptcha"
	ActionBypassLapi      = "bypassLapi"
	ActionBypassRateLimit = "bypassRateLimit"
	ActionCaptcha         = "captcha"
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
	ban           bool
	bypassCaptcha bool
	captcha       bool
	skipAppsec    bool
	skipLapi      bool
	skipRateLimit bool
}

// NewActionSet validates names and action tokens, then compiles predicates with New.
// An empty list succeeds and matches nothing. Inner errors are index-prefixed rule %d.
func NewActionSet(rules []ActionRule) (*ActionSet, error) {
	extracted := make([]Rule, len(rules))
	names := make([]string, len(rules))
	tokens := make([]actionTokens, len(rules))
	seenNames := make(map[string]struct{}, len(rules))
	for i, rule := range rules {
		name, err := CompileRowName(rule.Name, seenNames)
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

// ActionMatch is every matching row reduced for one request.
// BanName, CaptchaName and BypassCaptchaName are the first matching rule of that token. Empty means none.
// BypassCaptchaName means the request gets no captcha, so CaptchaName is empty whenever it is set.
// SkipLapi, SkipAppsec and SkipRateLimit are OR'd across every non-ban hit. A ban row contributes only its name.
// AmbiguousPathName is the first matching rule with a path predicate whose skips were dropped
// because the request path has more than one reading (see SingleReadingPath). Empty means none.
type ActionMatch struct {
	AmbiguousPathName string
	BanName           string
	BypassCaptchaName string
	CaptchaName       string
	SkipAppsec        bool
	SkipLapi          bool
	SkipRateLimit     bool
}

// Matching returns every matching index in list order. Cookie is parsed once when needed.
func (set *ActionSet) Matching(httpReq *http.Request) []int {
	if set == nil || set.set == nil {
		return nil
	}
	return set.set.Matching(httpReq)
}

// Fold reduces every matching row. A nil set matches nothing.
// The first ban name wins and that row contributes nothing else. Skip flags OR. The first captcha name wins.
// The first bypassCaptcha name wins, and it clears the captcha name: a request that gets no captcha has no captcha rule.
// A row with a path predicate skips no leg when the path has more than one reading: its regex saw
// one reading and the backend may serve another. Its captcha and bypassCaptcha tokens still apply.
func (set *ActionSet) Fold(httpReq *http.Request) ActionMatch {
	var match ActionMatch
	if set == nil {
		return match
	}
	reading := pathReading{requestURL: httpReq.URL}
	for _, i := range set.Matching(httpReq) {
		if set.Ban(i) {
			if match.BanName == "" {
				match.BanName = set.Name(i)
			}
			continue
		}
		if set.Captcha(i) && match.CaptchaName == "" {
			match.CaptchaName = set.Name(i)
		}
		if set.BypassCaptcha(i) && match.BypassCaptchaName == "" {
			match.BypassCaptchaName = set.Name(i)
		}
		if !set.skipsLeg(i) {
			continue
		}
		if set.set.hasPath(i) && reading.ambiguous() {
			if match.AmbiguousPathName == "" {
				match.AmbiguousPathName = set.Name(i)
			}
			continue
		}
		if set.SkipLapi(i) {
			match.SkipLapi = true
		}
		if set.SkipAppsec(i) {
			match.SkipAppsec = true
		}
		if set.SkipRateLimit(i) {
			match.SkipRateLimit = true
		}
	}
	if match.BypassCaptchaName != "" {
		match.CaptchaName = ""
	}
	return match
}

// pathReading answers SingleReadingPath once per Fold, on the first path row that would skip a leg.
type pathReading struct {
	requestURL      *url.URL
	checked         bool
	hasManyReadings bool
}

// ambiguous reports whether the request path has more than one reading.
func (r *pathReading) ambiguous() bool {
	if !r.checked {
		r.hasManyReadings = !SingleReadingPath(r.requestURL)
		r.checked = true
	}
	return r.hasManyReadings
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

// BypassCaptcha reports whether the row at index i has a bypassCaptcha token.
func (set *ActionSet) BypassCaptcha(i int) bool {
	return set != nil && i >= 0 && i < len(set.tokens) && set.tokens[i].bypassCaptcha
}

// SkipLapi reports whether the row at index i skips LAPI (bypass or bypassLapi).
func (set *ActionSet) SkipLapi(i int) bool {
	return set != nil && i >= 0 && i < len(set.tokens) && set.tokens[i].skipLapi
}

// SkipAppsec reports whether the row at index i skips AppSec (bypass or bypassAppsec).
func (set *ActionSet) SkipAppsec(i int) bool {
	return set != nil && i >= 0 && i < len(set.tokens) && set.tokens[i].skipAppsec
}

// SkipRateLimit reports whether the row at index i skips the rate limit (bypassRateLimit only).
func (set *ActionSet) SkipRateLimit(i int) bool {
	return set != nil && i >= 0 && i < len(set.tokens) && set.tokens[i].skipRateLimit
}

// skipsLeg reports whether the row at index i skips any leg: LAPI, AppSec, or the rate limit.
func (set *ActionSet) skipsLeg(i int) bool {
	return set.SkipLapi(i) || set.SkipAppsec(i) || set.SkipRateLimit(i)
}

// CompileRowName trims the name of one authoring row (an action rule or a rate-limit bucket) and
// rejects empty, colon, and a name already in seen. The caller adds the returned name to seen.
func CompileRowName(raw string, seen map[string]struct{}) (string, error) {
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

// compileActionTokens rejects empty, unknown, duplicate, ban mixed with other tokens, and captcha with bypassCaptcha.
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
		case ActionBypassCaptcha:
			parsed.bypassCaptcha = true
		case ActionBypassRateLimit:
			parsed.skipRateLimit = true
		default:
			return actionTokens{}, fmt.Errorf("action: unknown %q", token)
		}
	}
	if parsed.ban && len(seen) > 1 {
		return actionTokens{}, errors.New("action: ban must be alone")
	}
	if parsed.captcha && parsed.bypassCaptcha {
		return actionTokens{}, errors.New("action: captcha with bypassCaptcha")
	}
	return parsed, nil
}

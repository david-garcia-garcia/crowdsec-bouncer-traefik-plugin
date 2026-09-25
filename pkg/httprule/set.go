// Package httprule compiles HTTP request exemption rules (method, path, host, headers, cookies).
package httprule

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/textproto"
	"regexp"
	"strings"
)

const matchEverythingPattern = ".*"

// Set is a compiled list of rules. Match is OR; the first matching rule wins.
type Set struct {
	hasCookiePredicate bool
	rules              []compiledRule
}

// compiledRule is one compiled exemption. Nil regexp means any for that predicate.
type compiledRule struct {
	cookies   []valuePredicate
	headers   []valuePredicate
	hostRe    *regexp.Regexp
	methodAny bool
	methodNeg bool
	methodRe  *regexp.Regexp
	pathRe    *regexp.Regexp
}

// valuePredicate is a header or cookie check: nil pattern means the name is present.
type valuePredicate struct {
	name    string
	pattern *regexp.Regexp
}

// New compiles rules once. An empty list matches nothing. Fully empty rules and invalid RE2 fail.
func New(rules []Rule) (*Set, error) {
	set := &Set{rules: make([]compiledRule, 0, len(rules))}
	for i, rule := range rules {
		compiled, err := compileRule(rule)
		if err != nil {
			return nil, fmt.Errorf("rule %d: %w", i, err)
		}
		if len(compiled.cookies) > 0 {
			set.hasCookiePredicate = true
		}
		set.rules = append(set.rules, compiled)
	}
	return set, nil
}

// Match reports whether any compiled rule matches httpReq. First match wins.
// Cookie is parsed once only when this set has a cookie predicate.
func (set *Set) Match(httpReq *http.Request) bool {
	if set == nil || httpReq == nil {
		return false
	}
	// Parse Cookie once when hasCookiePredicate.
	var cookies []*http.Cookie
	if set.hasCookiePredicate {
		cookies = httpReq.Cookies()
	}
	// First matching rule wins.
	for i := range set.rules {
		if set.rules[i].match(httpReq, cookies) {
			return true
		}
	}
	return false
}

// compileRule rejects invalid syntax and a rule whose every predicate is any.
func compileRule(rule Rule) (compiledRule, error) {
	methodAny, methodNeg, methodRe, err := compileMethod(rule.Method)
	if err != nil {
		return compiledRule{}, fmt.Errorf("method: %w", err)
	}
	pathRe, err := compileOptionalRegexp(rule.Path)
	if err != nil {
		return compiledRule{}, fmt.Errorf("path: %w", err)
	}
	hostRe, err := compileOptionalRegexp(rule.Host)
	if err != nil {
		return compiledRule{}, fmt.Errorf("host: %w", err)
	}
	headers, err := compileValuePredicates(rule.Headers, true)
	if err != nil {
		return compiledRule{}, fmt.Errorf("headers: %w", err)
	}
	cookies, err := compileValuePredicates(rule.Cookies, false)
	if err != nil {
		return compiledRule{}, fmt.Errorf("cookies: %w", err)
	}
	if methodAny && pathRe == nil && hostRe == nil && len(headers) == 0 && len(cookies) == 0 {
		return compiledRule{}, errors.New("empty")
	}
	return compiledRule{
		cookies:   cookies,
		headers:   headers,
		hostRe:    hostRe,
		methodAny: methodAny,
		methodNeg: methodNeg,
		methodRe:  methodRe,
		pathRe:    pathRe,
	}, nil
}

// compileMethod trims, strips one leading !, and compiles Go RE2. Empty or .* without ! is any.
func compileMethod(raw string) (methodAny bool, methodNeg bool, methodRe *regexp.Regexp, err error) {
	pattern := strings.TrimSpace(raw)
	if strings.HasPrefix(pattern, "!") {
		rest := strings.TrimSpace(strings.TrimPrefix(pattern, "!"))
		if rest == "" {
			return false, false, nil, errors.New("empty negation")
		}
		if strings.HasPrefix(rest, "!") {
			return false, false, nil, errors.New("double negation")
		}
		methodNeg = true
		pattern = rest
	}
	if !methodNeg && (pattern == "" || pattern == matchEverythingPattern) {
		return true, false, nil, nil
	}
	methodRe, err = regexp.Compile(pattern)
	if err != nil {
		return false, false, nil, err
	}
	return false, methodNeg, methodRe, nil
}

// compileOptionalRegexp trims and compiles. Empty after trim is any (nil, nil).
func compileOptionalRegexp(raw string) (*regexp.Regexp, error) {
	pattern := strings.TrimSpace(raw)
	if pattern == "" {
		return nil, nil //nolint:nilnil // empty after trim is any, not a failure
	}
	return regexp.Compile(pattern)
}

// compileValuePredicates compiles a name→pattern map. canonicalize uses CanonicalMIMEHeaderKey.
func compileValuePredicates(raw map[string]string, canonicalize bool) ([]valuePredicate, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	predicates := make([]valuePredicate, 0, len(raw))
	for name, pattern := range raw {
		compiledName := strings.TrimSpace(name)
		if canonicalize {
			compiledName = textproto.CanonicalMIMEHeaderKey(compiledName)
		}
		pattern = strings.TrimSpace(pattern)
		var compiledPattern *regexp.Regexp
		if pattern != "" {
			var err error
			compiledPattern, err = regexp.Compile(pattern)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", compiledName, err)
			}
		}
		predicates = append(predicates, valuePredicate{name: compiledName, pattern: compiledPattern})
	}
	return predicates, nil
}

// match is AND of method, path, host, headers, then cookies.
func (rule compiledRule) match(httpReq *http.Request, cookies []*http.Cookie) bool {
	if !rule.matchMethod(httpReq.Method) {
		return false
	}
	path := ""
	if httpReq.URL != nil {
		path = httpReq.URL.Path
	}
	if rule.pathRe != nil && !rule.pathRe.MatchString(path) {
		return false
	}
	if rule.hostRe != nil && !rule.hostRe.MatchString(requestHostname(httpReq)) {
		return false
	}
	if !matchValuePredicates(rule.headers, httpReq.Header) {
		return false
	}
	return matchCookies(rule.cookies, cookies)
}

// requestHostname is the hostname of req.Host. SplitHostPort success drops the port.
func requestHostname(httpReq *http.Request) string {
	if hostname, _, err := net.SplitHostPort(httpReq.Host); err == nil {
		return hostname
	}
	return httpReq.Host
}

// matchMethod applies unanchored RE2 on req.Method. Any always matches. methodNeg inverts.
func (rule compiledRule) matchMethod(method string) bool {
	if rule.methodAny {
		return true
	}
	matched := rule.methodRe.MatchString(method)
	if rule.methodNeg {
		return !matched
	}
	return matched
}

// matchValuePredicates is AND across names. Empty pattern is present; else one RE2 hit is enough.
func matchValuePredicates(predicates []valuePredicate, header http.Header) bool {
	for _, predicate := range predicates {
		values := header[predicate.name]
		if len(values) == 0 {
			return false
		}
		if predicate.pattern == nil {
			continue
		}
		if !oneValueMatches(predicate.pattern, values) {
			return false
		}
	}
	return true
}

// matchCookies is AND across cookie names. Names are case-sensitive.
func matchCookies(predicates []valuePredicate, cookies []*http.Cookie) bool {
	for _, predicate := range predicates {
		values := cookieValues(cookies, predicate.name)
		if len(values) == 0 {
			return false
		}
		if predicate.pattern == nil {
			continue
		}
		if !oneValueMatches(predicate.pattern, values) {
			return false
		}
	}
	return true
}

// oneValueMatches is true when pattern matches any value (unanchored MatchString).
func oneValueMatches(pattern *regexp.Regexp, values []string) bool {
	for _, value := range values {
		if pattern.MatchString(value) {
			return true
		}
	}
	return false
}

// cookieValues collects values whose names equal name (case-sensitive).
func cookieValues(cookies []*http.Cookie, name string) []string {
	var values []string
	for _, cookie := range cookies {
		if cookie.Name == name {
			values = append(values, cookie.Value)
		}
	}
	return values
}

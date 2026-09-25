# Standards

1. [hard] Leave a trail — `pkg/httprule/set.go:54` — Match has a Cookie-parse block and an OR scan with no block intros; the method comment does not say Cookie is parsed once only when this set has a cookie predicate
   Fix: Introduce each block in one line: parse Cookie once when hasCookiePredicate, then first matching rule wins
   Quote:
      ```
      // Match reports whether any compiled rule matches httpReq. First match wins.
      func (set *Set) Match(httpReq *http.Request) bool {
      	if set == nil || httpReq == nil {
      		return false
      	}
      	var cookies []*http.Cookie
      	if set.hasCookiePredicate {
      		cookies = httpReq.Cookies()
      	}
      ```
   Status: done
   Argument: Added Cookie-parse and first-match-wins block intros on `Match` in `pkg/httprule/set.go`.
2. [judgement] Duplicated Code — `pkg/httprule/set.go:190` — `matchValuePredicates` and `matchCookies` copy the same AND-across-names / empty-present / one-RE2-hit loop and differ only in value lookup
   Fix: One matcher that takes a name→values lookup; call it from both
   Quote:
      ```
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
      ```
   Status: skipped
   Argument: judgement; header vs cookie lookups stay separate at this size.

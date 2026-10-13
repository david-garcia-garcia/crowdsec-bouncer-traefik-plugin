# Standards

1. [judgement] Duplicated Code — `pkg/httprule/set.go:57` — `Match` and `Matching` walk the same compiled rules and cookie parse
   Fix: Keep `Match` as dest first-wins; leave the walk unless a later caller needs one helper
   Status: skipped
   Argument: judgement; dest Match stays first-wins; not applied unattended.
   Quote:
      ```
      func (set *Set) Match(httpReq *http.Request) bool {
      ...
      func (set *Set) Matching(httpReq *http.Request) []int {
      ```

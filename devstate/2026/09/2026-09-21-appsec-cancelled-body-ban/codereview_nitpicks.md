# Nitpicks

1. [hard] Clear conditions — `pkg/appsec/query.go` — client-gone branch in `newAppsecBodyRequest` gates ban/captcha on `faErr != nil` after `resultForFailureActionErr`, so passthrough is only visible by knowing that helper returns a nil error for passthrough rather than naming passthrough (or ban/captcha) here.

```go
		bodyBytes, err := io.ReadAll(teeReader)
		if err != nil {
			if isClientGoneBodyReadErr(err) {
				if faErr := resultForFailureActionErr(pol.FailureAction, "appsecQuery:clientBodyDropped"); faErr != nil {
					return nil, faErr
				}
				return nil, errClientBodyDroppedAllow
			}
			return nil, fmt.Errorf("appsecQuery:GetBody %w", err)
		}
```

   → Guard passthrough first (`EffectiveFailureAction == FailureActionPassthrough` then `errClientBodyDroppedAllow`), else `return nil, resultForFailureActionErr(...)`; or a predicate named for client-gone failure-action routing.
   Status: done
   Argument: builder returns `errClientBodyDropped`; `Query` maps via `resultForFailureAction` which names passthrough/ban/captcha.

2. [hard] Symmetry and consistency — `pkg/appsec/query.go` — in the same `newAppsecBodyRequest` switch, unreadable-body ban uses an explicit passthrough exclusion on `pol.FailureAction`, while the new client-gone branch uses the `faErr != nil` indirection; same failure-action role, different condition shape for the reader.

```go
	case isBodyUnreadable(httpReq):
		if isMethodWithBody(httpReq.Method) && configuration.EffectiveFailureAction(pol.FailureAction) != configuration.FailureActionPassthrough {
			return nil, resultForFailureActionErr(pol.FailureAction, "appsecQuery:unreadableBody dropped")
		}
```

   → Align client-gone handling with the explicit `EffectiveFailureAction` check (or shared helper) used on the unreadable-body branch.
   Status: done
   Argument: builder classifies only; `Query` uses `resultForFailureAction` (same owner as unreachable/500), not `faErr != nil`.

3. [hard] Symmetry and consistency — `pkg/appsec/query.go` — `Query` maps other failure-action passthrough outcomes via `resultForFailureAction` in place, but client-body-dropped passthrough requires a prior sentinel from `newAppsecBodyRequest` and a separate `errors.Is` + `appsecAllow()` block at the top of `Query`.

```go
func (c *Client) Query(ip string, httpReq *http.Request, pol Policy) (*Response, error) {
	req, err := c.newAppsecForwardRequest(ip, httpReq, pol)
	if errors.Is(err, errClientBodyDroppedAllow) {
		return appsecAllow(), nil
	}
	if err != nil {
		return nil, err
	}
	// ...
		return resultForFailureAction(pol.FailureAction, "appsecQuery:unreachable")
```

   → Route client-gone passthrough through the same `resultForFailureAction` entry point as unreachable/500/readBody (e.g. typed build error handled once in `Query`), so passthrough allow is not a one-off sentinel path.
   Status: done
   Argument: `Query` maps `errClientBodyDropped` through `resultForFailureAction`.

4. [hard] Name for the scope — `pkg/appsec/zzz_query_test.go` — loop variable `readErr` is the whole `{name, err}` case row, not the simulated read error (`readErr.err`), which mislabels the value for the rest of the subtests.

```go
	for _, readErr := range clientGoneErrs {
		t.Run(readErr.name+"/passthrough", func(t *testing.T) {
			assertClientBodyDroppedPassthrough(t, readErr.err)
		})
		t.Run(readErr.name+"/ban", func(t *testing.T) {
			assertClientBodyDroppedBan(t, readErr.err)
		})
	}
```

   → Rename the range variable to the case role (e.g. `goneCase`, `tc`).
   Status: done
   Argument: range variable renamed to `goneCase`.

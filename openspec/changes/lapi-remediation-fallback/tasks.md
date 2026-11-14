# Tasks

## 1. Config knob

- [x] 1.1 Add `LapiRemediationFallback` (`json:"lapiRemediationFallback,omitempty"`) to `Config` between `LapiRedisReadHosts` and `LapiScheme`, constants `LapiRemediationFallbackBan` / `Captcha` / `Ignore`, default `ban` in `configuration.New`, and `EffectiveLapiRemediationFallback` (empty → `ban`); verify `go build ./...`
- [x] 1.2 Validate the enum in `validateParamsRequired` (empty passes; other values fail naming `LapiRemediationFallback`; `captcha` not gated on a captcha instance); verify with `pkg/configuration/zzz_configuration_test.go` cases for omitted, empty, `ban`, `captcha` without captcha instance, `ignore`, and `allow` (rejected)
- [x] 1.3 Add the `LapiRemediationFallback` README Variables entry: values, default `ban`, set it on the middleware that connects to LAPI, captcha on a router without captcha serves the ban page, and that it is not `bouncerLapiFailureAction`; verify the entry sits in the Lapi* block in alphabetical order

## 2. LAPI ingest and delete

- [x] 2.1 Read the effective fallback in `lapi.New` onto `Client`; make `ingestRemediationKind` return `t` / `c` / `""` for unknown types per the fallback and add the `fallback` attribute to the TRACE `handleStreamCache:unknownType` record; verify the TRACE test asserts the attribute and no Info/Debug record
- [x] 2.2 Treat empty ingest kind as not stored in `streamPutItem` and the Range New branch of `fetchAndApplyStreamDecisions` (skipped rows do not count); verify tests: under `ignore`, stream New `throttle` leaves the Ip slot, a header-scope slot, and `range-index` empty; under `captcha` they store `c`; under `ban` they store `t`
- [x] 2.3 Add `deletedTypeClearsStore` on `Client` and use it in `streamDeleteItem` and the Range Deleted branch (skipped rows do not count); verify tests: under `ignore`, a later Deleted `throttle` row keeps an Ip ban and a Range ban; under `ban`, it clears the Ip slot
- [x] 2.4 Verify live pick with tests: under `ignore`, a `throttle`-only list is `f` and `throttle` then `captcha` is `c`; under `ban`, `throttle` then `captcha` is `t`; under `captcha`, `throttle` then `ban` is `t`; a subscriber's `ignore` with an opener default still stores `t`
- [x] 2.5 Replace `allow` with `throttle` as the sample unknown type in `pkg/lapi/zzz_unknown_decision_type_test.go` (keep `challenge`); verify no test in `pkg/` asserts allow semantics (`grep -rn '"allow"' pkg/`)
- [x] 2.6 Update usage devdocs: Language **Remediation fallback** plus usage lines in `knowledge/devdocs/core_plugin_lapi_stream-apply.md`, and `knowledge/devdocs/core_plugin_lapi_origin-based-decision-remap.md` (unknown type follows the fallback; remap follows the stored letter; nothing to remap under `ignore`), each with the whitelist / allow position; verify neither says "any other type is ban" without the knob

## 3. Store identity

- [x] 3.1 Add `remediationFallback` (`omitempty`, filled only when the effective value is not `ban`) to `streamSession` and `ownership`; verify tests: omitted and `ban` give the same `SessionHex` as the pre-knob payload, `ignore` changes both `SessionHex` and `OwnershipKey`
- [x] 3.2 Add the knob to the Ownership key and SessionHex terms and the How-to-use bullets in `knowledge/devdocs/core_plugin_lapi_reclaim-key.md`; verify it reads "new Client and new store" like `lapiDefaultDecisionSeconds`

## 4. Position docs and debt

- [x] 4.1 Add one README paragraph under "## Decisions" after the scope list: `whitelist` and `allow` are not valid CrowdSec decision types and are an inadequate way to manage whitelists, because the LAPI stream is designed to say WHAT TO BLOCK, not WHAT TO ALLOW; allowing traffic is done upstream by parser whitelists and LAPI allowlists (`cscli allowlists`), which stop or expire decisions at the source; cite upstream issue #402 point 1, upstream PR #403 point 1, upstream PR #433 (whitelist part), and fork PR #198; verify the README does not say allowlists "never reach a bouncer"
- [x] 4.2 Edit `knowledge/debt/2026-09-19-multiple-decisions-per-cache-key.md`: remove the allow-as-veto framing (Why allow example, Risks, Observed allow lines, Required shape allow-means-pass, apply-order allow parts, Restore the real-stack test, the restore-requirement line, and the Recovered Pester file); replace the stale "stream skips `type=allow`" line with "unknown types follow `lapiRemediationFallback`"; keep two bans, ban + captcha, and the typed delete clearing the whole slot; verify `grep -n "Allow is a whitelist\|allow-as-veto" knowledge/` returns nothing
- [x] 4.3 Remove the allow-over-ban Pester pointer from `knowledge/devdocs/build_e2e_real.md`; verify the file no longer references that test

## 5. Verify

- [x] 5.1 Run `go vet ./...` and `go test ./...` in the worktree and verify both pass
- [x] 5.2 Run `openspec validate lapi-remediation-fallback` and verify it passes

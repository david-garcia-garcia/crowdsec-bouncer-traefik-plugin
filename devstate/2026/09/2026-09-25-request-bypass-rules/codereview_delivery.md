# Delivery

## Motivation

ServeHTTP already skips CrowdSec at two sites after trusted-IP skip and forced `b`: the LAPI decision path (`LookupRemediation`, `LiveLookup`, missing-LAPI failure, stream-unhealthy failure) and the AppSec hop (body buffer and Query). The knobs for those skips are `bouncerLapiExcludeRegex` and `bouncerAppsecExcludeRegex`: one unanchored RE2 each, compiled by `CompileExcludeRegex`, matched against a reconstructed `host://path`. Host is `req.Host` after `SplitHostPort` when that call succeeds; path is `req.URL.Path` with one leading `/` stripped (empty or `/` becomes `host://`). Example: Host `example.com` Path `/health` → `example.com://health`. Those two strings landed the same day as this ticket.

An operator who needs to skip one leg cannot say it as method, path, headers, and cookies. A `GET /healthz` probe with `X-Health: ok`, an `OPTIONS` preflight, or a cookie-gated path has no authoring form. `health` only matches if that substring appears in `host://path`; it does not mean Path `/unhealthy`. `example.com://health` is the match text, not `/health`. Method is not a predicate. Header and cookie maps do not exist. The two legs can already skip independently, but only through that same host+path string. There is no mock or real e2e that Traefik decodes those knobs and that a banned IP on a matching path reaches origin.

Left alone, `host://path` freezes as the public skip contract. Probe and health traffic that should skip LAPI still takes a store ban or live lookup; AppSec still buffers and queries paths that should skip the hop. Operators keep writing host-qualified patterns that cannot name a header or a cookie. Nothing proves the skip through a Traefik file-provider load.

Priority: P2 — real operator pain, with a workaround or limited blast radius

## Implementation

Replace the two exclude strings with `bouncerAppsecBypassRules` and `bouncerLapiBypassRules` (`[]httprule.Rule`). Compile-once lives in `pkg/httprule` (stdlib only): `New` rejects invalid RE2, `!!`, a leading `!` with no pattern, and a rule whose every predicate is any (`{}` or `{method: ".*"}`); a method-only rule is valid. `ValidateParams` calls `New` so `plugin.New` fails before LAPI Open (error names the Go field); `bouncer.New` compiles again and stores `*httprule.Set`. Request check is `Set.Match`: OR across rules, first wins; AND method → path → headers → cookies. Method and path are unanchored RE2 on `req.Method` and `req.URL.Path`; optional leading `!` negates method; the plugin does not insert `^`/`$` or fold case. Headers use `CanonicalMIMEHeaderKey`; cookies are case-sensitive; Cookie is parsed once per request only when that set has a cookie predicate.

ServeHTTP keeps the exclude skip sites: after forced `b`, a LAPI match goes to `passOrForcedCaptcha`; in `handleNextServeHTTP`, an AppSec match calls `next` with no buffer and no Query. Trusted-IP, forced `b`, and startup-block 503 still run first. `recordProcessed` stays where it is. Bypass lists stay off reclaim keys. `CompileExcludeRegex`, `excludeMatchString`, and `excludedBy` are deleted. Mock e2e `request-bypass-rules` proves Traefik nested-list decode, LAPI skip of a banned IP on `/healthz`, AppSec skip of mock `rpc2` on `/foo/403-skip`, and independence.

## What this changes
**Operators.** **BREAKING:** drop `bouncerAppsecExcludeRegex` / `bouncerLapiExcludeRegex` (leftover YAML is ignored) and author `bouncerAppsecBypassRules` / `bouncerLapiBypassRules`; path is unanchored RE2 on `req.URL.Path` so `health` matches `/unhealthy`.
**Admin users.** None.
**Developers.** Public Config replaces the two exclude strings with `BouncerAppsecBypassRules` / `BouncerLapiBypassRules` (`[]httprule.Rule`); `CompileExcludeRegex` is removed; `httprule.New` / `Set.Match` is the compile-and-match contract, and the lists stay off reclaim keys.
**End users.** None.

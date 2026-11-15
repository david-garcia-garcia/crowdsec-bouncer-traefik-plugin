## Context

See proposal.md. Both fixes live where the fold result is built, so `serveLAPI`, `serveAppSec` and the captcha path keep reading one `ActionMatch`.

## Decisions

1. **Ambiguity check in `httprule.Fold`, challenge override in `bouncer.foldActionRules`.** The single-reading rule is about how a path predicate reads the request, so it belongs with the predicates. The challenge prefix is a bouncer concept (`crowdsecChallengeCallbackPrefix`), so the override stays in `pkg/bouncer`. `httprule` keeps importing only the standard library.
2. **Same criterion as upstream `pkg/location.isCanonicalPath` plus `Path == EscapedPath()`.** Allowed bytes `A-Z a-z 0-9 - . _ ~ ! $ & ' ( ) + , = : @ /`; `path.Clean` must not change it (trailing slash kept); no dots-only segment. Alternative: decode / clean the path ourselves and match that — rejected, the plugin cannot know which reading the backend picks.
3. **Drop only skips, per row with a `path` predicate.** A captcha token is a gate, not an exemption, so it stays. Host / header / cookie / method-only rows do not read the path. Ban rows are left alone: treating every ambiguous path as a ban match would ban legitimate percent-encoded paths. Ban / captcha rules can still be evaded by an ambiguous path the backend resolves into their prefix; that is a follow-up, not this change.
4. **Override the AppSec skip only.** `bypass` on the challenge prefix keeps its LAPI skip, so a health or internal rule does not start failing on LAPI outages.
5. **TRACE, not WARN.** Both conditions are client-driven; a WARN would let any client fill the log.

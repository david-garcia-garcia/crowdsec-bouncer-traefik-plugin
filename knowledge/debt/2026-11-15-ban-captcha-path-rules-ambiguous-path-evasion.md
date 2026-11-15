# Ban and captcha path rules can be evaded by an ambiguous path

IssueKey: 2026-10-13-count-challenge-once
Size: large
Action: note

## Why this follow-up
`bouncerActionRules` ban and captcha rows with a path predicate match the decoded `URL.Path`. A path with more than one reading that the backend resolves into the rule's prefix (for example `/x/..;/admin` against `^/admin`, read as `/admin` by a Java servlet container) does not match the rule, so the ban or captcha is not applied.

## Why it was not taken
This change only made skip rows (`bypass*`) fail safe on ambiguous paths, where dropping the skip just means AppSec inspects the request. For ban and captcha rows the fail-safe answer is to apply the remediation to an ambiguous path, which can hit legitimate traffic and needs its own design and spec.

## Risks
An operator who protects a backend prefix with a ban or captcha path rule can be bypassed by a client that sends an ambiguous path to a backend that normalizes it.

## Context
Skip rows already use `httprule.SingleReadingPath` in `Fold` (`pkg/httprule/path.go`, `pkg/httprule/action.go`). Spec `core_plugin_middleware_bouncer` requirement "Action-rule skips need a single-reading path".

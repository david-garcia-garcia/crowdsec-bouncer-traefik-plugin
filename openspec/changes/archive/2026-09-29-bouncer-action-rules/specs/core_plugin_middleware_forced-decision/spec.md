## REMOVED Requirements

### Requirement: Empty crowdsecDecisionHeader leaves lookup unchanged
**Reason**: `bouncerDecisionHeader` is deleted. Force ban/captcha is an action rule.
**Migration**: Omit the old key. To restore dest `b`/`c`, add `bouncerActionRules` rows whose header patterns are `^b$` / `^c$`. Leftover YAML is dropped by Traefik unused-key decode.

### Requirement: Configured header b skips stream and live lookup
**Reason**: Matching `action: [ban]` on `bouncerActionRules` is the remaining ban-without-lookup path.
**Migration**: `{name: <id>, headers: {<Header>: "^b$"}, action: [ban]}`. Header match is unanchored RE2 against each value, not `Header.Get` exact trim.

### Requirement: Header c does not override an internal ban
**Reason**: Matching `action: [captcha]` keeps dest "LAPI ban beats header c". `[captcha, bypassLapi]` is stronger and is not the old header.
**Migration**: `{name: <id>, headers: {<Header>: "^c$"}, action: [captcha]}`. WARN `ServeHTTP:forcedCaptchaSuperseded` now logs `name`, not `header`.

### Requirement: Other header values are ignored
**Reason**: There is no force-header token table. Non-matching header values simply fail the action-rule header predicate.
**Migration**: None. Unknown tokens are not a special case.

### Requirement: Forced captcha still honors the gate cookie
**Reason**: A captcha action rule reuses the existing captcha gate. Valid cookie pass is owned by that gate plus the action-rules requirement on `core_plugin_middleware_bouncer`.
**Migration**: Keep the gate cookie. After it is valid, AppSec still runs unless a matching skip skipped it.

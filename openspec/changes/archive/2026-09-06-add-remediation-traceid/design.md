## Context

See proposal.md. `TraceHeadersCustomName` copies an incoming request header into the ban template only. Captcha templates have `SiteKey`, `FrontendJS`, `FrontendKey`. `RemediationHeadersCustomName` already writes a response header on ban, captcha HTML, and solved-captcha. Explore: this plugin owns a new per-response ID when `RemediationTraceIDCustomName` is set; Traefik and hop headers are not the owner. Cf-Ray is 16 hex plus a colo this process does not have.

## Goals / Non-Goals

**Goals:**
- Operator knob `RemediationTraceIDCustomName`; empty disables.
- 16 lowercase hex from `crypto/rand` on ban HTML and captcha HTML.
- Same value on the configured response header and `{{ .TraceID }}`.
- Incoming `TraceHeadersCustomName` unchanged when the new knob is empty.

**Non-Goals:**
- Removing `TraceHeadersCustomName`.
- Trace headers on pass-through or AppSec challenge bodies.
- Trace header on solved-captcha 302.
- Fake Cloudflare colo suffix.
- Reconstructing `Cf-Ray` / `X-Request-ID` from the request.

## Decisions

1. **Knob name and default.** `RemediationTraceIDCustomName` / json `remediationTraceIdCustomName`, default `""`. Alternative: reuse `TraceHeadersCustomName` as a response header — rejected; that name is incoming passthrough today.

2. **Owner of the ID.** Bouncer generates one ID per remediation HTML response and passes it into `captcha.ServeHTTP`. Captcha MUST NOT generate a second ID. Alternative: both packages call `crypto/rand` — rejected; One job, one owner.

3. **Format.** 8 bytes from `crypto/rand`, encoded as 16 lowercase hex. No hyphen, no colo. Read error: log warn, omit header and `TraceID`, still serve the page.

4. **Coexistence.** If `RemediationTraceIDCustomName` is non-empty, that ID is `{{ .TraceID }}` and the response header. Incoming `TraceHeadersCustomName` is used only when the built-in knob is empty (ban path today).

5. **Surfaces.** Set the response header before `WriteHeader` on ban (including HEAD) and captcha HTML. Do not set it on solved-captcha redirect or AppSec relay.

6. **Yaegi.** `crypto/rand` and `encoding/hex` are stdlib. No `useUnsafe`. Keep `CreateConfig` / `New` on the module root.

## Risks / Trade-offs

- [RNG fail] → omit TraceID rather than fail closed; ban/captcha still work.
- [Both knobs set] → operators who still send `X-Trace` will not see that value in the template; documented as built-in wins.
- [Captcha `ServeHTTP` signature] → add a `traceID` argument (or equivalent field on a small per-request value). Do not add a package global.

## Migration Plan

Document the new key in README next to `TraceHeadersCustomName`. Existing empty default is a no-op. Rollback: previous tag.

# Explore
IssueKey: 2026-09-06-upstream-358-builtin-traceid

## Concepts

Ban and captcha HTML are the only pages this plugin authors. Today `TraceHeadersCustomName` copies an **incoming** request header into the ban template as `{{ .TraceID }}`. It never generates an ID and never sets a response header. Captcha templates have no `TraceID` field. `RemediationHeadersCustomName` is the sibling pattern: empty disables; when set, the plugin writes a response header on ban / captcha / solved-captcha.

```
DestBranch today
  request header (optional, third-party plugin) ──► TraceHeadersCustomName ──► ban {{ .TraceID }}
  (captcha template: SiteKey, FrontendJS, FrontendKey only)

Desired
  RemediationTraceIDCustomName set ──► generate 16-hex ID ──► response header + {{ .TraceID }}
                                    on ban HTML and captcha HTML only
  TraceHeadersCustomName unchanged when the new knob is empty
```

Traefik does not mint a request ID. `Cf-Ray` is Cloudflare's header when that hop exists (`knowledge/research/ext_cloudflare_http-headers_cf-ray/`). Incoming `X-Request-ID` / `Cf-Ray` stay owned by those hops. Built-in generation is a new fact this plugin owns per remediation **response**, not a reconstruction of client address, Host, or an upstream trace.

Generation is per HTML response (`crypto/rand`, Yaegi stdlib — this tree already imports `crypto/tls`). Ban and captcha each write their own headers; bouncer generates the ID and passes it into captcha `ServeHTTP` so captcha does not import bouncer and we do not copy the RNG.

## Decisions

- Add `RemediationTraceIDCustomName` (json `remediationTraceIdCustomName`), default empty = off, next to `RemediationHeadersCustomName` in `pkg/configuration`.
- Keep `TraceHeadersCustomName` as incoming passthrough for ban only.
- Built-in ID format: 16 lowercase hex characters (8 bytes from `crypto/rand`). No invented colo suffix.
- Inject the configured response header and `{{ .TraceID }}` on ban HTML and captcha HTML (including HEAD: header yes, body no). Not on pass-through, not on solved-captcha 302, not on AppSec challenge bodies.
- Tests: unit on ban + captcha for header + template; mock e2e on existing custom-ban-page and captcha scenarios when the knob is wired.

## Open questions

- Q: Who already owns the request/trace ID (client address, Host, hop headers, Traefik, Cloudflare)?
  Decision: assumed — Traefik does not generate one. Incoming `TraceHeadersCustomName` is owned by whoever set that request header. `Cf-Ray` is Cloudflare's when that hop is present. When `RemediationTraceIDCustomName` is set, this plugin owns a new per-remediation-response ID and must not copy or reconstruct hop headers.
  By: explore

- Q: Exact CF-Ray–style ID format (length, charset, entropy, colo suffix)?
  Decision: assumed — 16 lowercase hex from `crypto/rand` (8 bytes), matching the hashed prefix in Cloudflare's example `230b030023ae2822-SJC`. No three-letter colo; this process has none. `crypto/rand` Read error: log warn and omit header/`TraceID`; still serve the ban/captcha page.
  By: explore

- Q: Precedence when both `TraceHeadersCustomName` and `RemediationTraceIDCustomName` are set?
  Decision: assumed — built-in generation wins for `{{ .TraceID }}` and the response header. Incoming passthrough runs only when the built-in knob is empty (backward compatible).
  By: explore

- Q: Should captcha solved-captcha 302 also carry the trace header?
  Decision: assumed — no. Ticket names ban and captcha **pages**. Solved is a redirect; `RemediationHeadersCustomName` already marks that response.
  By: explore

- Q: Should AppSec challenge HTML get a built-in TraceID header?
  Decision: assumed — no. Ticket names ban and captcha pages. AppSec bodies are AppSec's envelope; out of scope.
  By: explore

# Explore
IssueKey: 2026-09-06-appsec-query-hardening

## Concepts
Four defects share one AppSec forward round-trip in `pkg/appsec/query.go`: early return before `drainResponse`, stale outbound body headers, read errors bypassing `resultForFailureAction`, and `appsecBodyLimit == 0` falling through to a bodyless GET.

Connection reuse tests exist for 200/403/500 but not 502/503/504. `pkg/bouncer/bouncer.go` already strips hop-by-hop headers when writing AppSec responses to the client; the forward path has no equivalent filter.

## Decisions
- Drain on every non-nil `*http.Response` before any failure-action return, including 502/503/504. Measured: `defer` at line 103 never runs when line 99–101 returns first.
- Rebuild outbound headers after the POST body is fixed: skip hop-by-hop, `Content-Length`, and `Transfer-Encoding` from the client copy; set `Content-Length` from bytes actually sent.
- Route `readCappedAppsecBody` errors through `resultForFailureAction` like 500/unreachable paths.
- `crowdsecAppsecBodyLimit: 0` means **unlimited** (read and forward the full POST body). Default remains 10 MiB when omitted; only explicit `0` disables the cap. No silent GET downgrade.
- Keep validation in `pkg/configuration` unchanged this run (0 stays valid); document unlimited semantics in spec and code comment only.

## Open questions
- Q: What should `crowdsecAppsecBodyLimit: 0` mean?
  Decision: assumed — `0` is unlimited body forward; no validation change in this bounded `pkg/appsec` run.
  By: explore

- Q: Should hop-by-hop filtering reuse `pkg/bouncer.isHopByHopHeader`?
  Decision: assumed — duplicate the small header-name list in `pkg/appsec` to stay within scope; no cross-package export.
  By: explore

- Q: Do response read errors count as infrastructure failure or AppSec verdict?
  Decision: assumed — transport/read/parse-cap failures use `failureAction`; non-200 empty bodies without envelope remain ban (unchanged).
  By: explore

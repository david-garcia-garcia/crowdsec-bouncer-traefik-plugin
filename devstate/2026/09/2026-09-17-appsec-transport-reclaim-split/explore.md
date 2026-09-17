# Explore
IssueKey: 2026-09-17-appsec-transport-reclaim-split

## Concepts

AppSec reclaim is **not** a field-for-field LAPI mirror.

```
AppSec identity today (pkg/appsec/session.go identity)
  listener:  scheme, host, path, key
  query cap: bodyLimit          ← write-once Client scalar; copies req body
  transport: httpTimeoutSeconds ← shared HTTPTimeoutSeconds
             tlsInsecureVerify, tlsCa, tlsCert  ← CrowdsecAppsecTLS* content
  not hashed: crowdsecAppsecFailureAction (already on Bouncer + appsec.Policy)
              middleware name, next, templates, Enabled, LAPI fields
              *File TLS paths (GetTLSConfigCrowdsec resolves into content)

LAPI identity after PR #62 (pkg/lapi/identity.go) — read only
  first-wins: mode, LAPI URL+key, CAPI, intervals, Redis host/auth/db
  dropped:    HTTP timeout, LAPI TLS, per-router policy, StreamStartupBlock
  extra:      stream vs live keys, PeekLivePrefix warn-and-wire
```

```
DestBranch failure (TLS- or timeout-only AppSec reload)

  New(cfg') ──► Key(cfg') ≠ Key(cfg) ──► OpenWithHooks create
       │                                        │
       │                                        ▼
       │                                 new *appsec.Client
       │                                 old Client → grace/Close
       ▼
  last New cannot Adopt: Open returns the new object; httpClient is soldered
```

`Client.httpClient` is a write-once `*http.Client`. `Query` reads it with no mutex. Only `Close` locks. `Open` does not call Adopt. Session tests only assert same-config reclaim (`pkg/appsec/zzz_session_test.go`).

Per-router AppSec policy is already off the key: `Bouncer.appsecFailureAction` → `appsec.Policy` at `Query` (`pkg/bouncer/bouncer.go`, `pkg/appsec/query.go`). `core_plugin_appsec_failure-action` already says that.

Live spec `core_plugin_appsec_client` still requires TLS, body limit, and HTTP timeout in the key. That is the spec delta, not extra product scope.

Yaegi: store replaceable transport as `atomic.Value` with the same comment as `pkg/lapi/client.go`. Do not use `atomic.Pointer[T]`. Do not mutate remaining write-once scalars (`appsecScheme`, `appsecHost`, `appsecPath`, `appsecBodyLimit`). Traefik `New` ctx stays the reclaim holder (`std_go_reclaim`).

Client IP is already owned: `pkg/ip.GetRemoteIP` → `bouncer` `clientRequest` (`req`). `Query` takes that `ip`. Do not reconstruct `RemoteAddr`.

## Decisions

- Drop `HTTPTimeoutSeconds` and the three AppSec TLS content fields from `identity` / `IdentityHex` / `Key`.
- Keep listener URL + key + `bodyLimit` on the key.
- Extract unexported `transport` (HTTP client, API key, timeout, AppSec TLS extras) in `pkg/appsec/client_http.go`. Store on `Client` as `atomic.Value`. `New` Stores the first value; `Open` calls `AdoptTransport(cfg)` after bind so last `New` wins. Idle-close the previous `*http.Client`.
- `Query` / `Close` read `currentTransport()`. Remove write-once `appsecKey` and `httpClient` (do not mutate them in place).
- `plugin.go` stays unchanged. No `pkg/captcha/` edit. No `pkg/bouncer/` edit unless Open/Query signatures force it (they should not).
- Spec host: `core_plugin_appsec_client` only. Do not edit `core_plugin_middleware_instance-reclaim`, `pkg/lapi/`, `pkg/reclaim/` internals.
- Close `knowledge/debt/2026-09-17-appsec-captcha-split.md` when implement lands.

## Open questions

- Q: Does `CrowdsecAppsecBodyLimit` stay on the AppSec reclaim key?
  Decision: resolved — keep it on identity and as write-once `appsecBodyLimit`. It is the request-copy cap in `newAppsecBodyRequest`, not HTTP transport. Ticket forbade moving it unless explore showed it is transport.
  By: explore

- Q: Is `HTTPTimeoutSeconds` the only timeout, and which TLS knobs are AppSec's?
  Decision: resolved — yes, the shared `HTTPTimeoutSeconds`. No AppSec-specific timeout field. TLS is `GetTLSConfigCrowdsec(..., true)` from `CrowdsecAppsecTLSInsecureVerify` / `TLSCertificateAuthority` / `TLSCertificateBouncer` (content). `*File` knobs resolve into those strings; they are not hashed today.
  By: explore

- Q: Can `plugin.go` stay unchanged if `AdoptTransport` lives inside `appsec.Open`?
  Decision: resolved — yes. Mirror `lapi.OpenLive`: bind, then `AdoptTransport(cfg)`. `plugin.go` already only calls `appsec.Open`.
  By: explore

- Q: Does AppSec API key move onto `transport` like LAPI, or stay a write-once Client field?
  Decision: resolved — put HTTP+auth on `transport` (client, key, timeout, TLS extras). Keep key in identity so a key change still opens a new Client. Remove write-once `appsecKey`; `Query` reads the key from `currentTransport()`. Do not convert the old field into a mutable scalar.
  By: explore

- Q: Is there a second per-router AppSec policy still on the Client or in the key?
  Decision: resolved — no. Failure action is already on Bouncer + `Policy` at Query and is not in `identity`. Do not invent a second policy move. `core_plugin_appsec_failure-action`, bot-detection, and captcha-gate need no reclaim-key delta.
  By: explore

- Q: Does this apply need `pkg/captcha/` or `pkg/bouncer/` edits?
  Decision: resolved — no captcha edit. No bouncer edit unless Open/Query signatures change (they should not). Fence stays `pkg/appsec/` + `core_plugin_appsec_client`.
  By: explore

- Q: Who already owns client address / Host for the AppSec forward?
  Decision: resolved — `pkg/ip.GetRemoteIP` via `bouncer` `clientRequest` (`req`). `Query` takes that `ip` and `httpReq.Host`. Reuse; do not reconstruct from `RemoteAddr`.
  By: explore

- Q: Should AppSec emit LAPI-style INFO on transport replace (`sessionKey`, adopted)?
  Decision: assumed — yes, INFO `appsec transport replaced` with reclaim `Key` when timeout/TLS extras change. No `ignored` joiner path: AppSec has one `Key`, no `PeekLivePrefix`.
  By: explore

- Q: Will a sibling merge move `origin/master` before implement or pullrequest?
  Decision: assumed — run Sync (fetch + merge `origin/master`, do not rebase a pushed branch) before implement and before pullrequest; re-verify after merge.
  By: explore

# AppSec bot-detection challenge

Wire protocol CrowdSec AppSec uses to serve bot-detection challenges through a remediation component (bouncer). Pin: engine `github.com/crowdsecurity/crowdsec@cc76dbbce40bd2e6a3ce1ba07e3c41d8b462de66` (`v1.8.0`). Live official pages on 2026-09-05 are under `/docs/next/appsec/bot_detection/`; the named `/docs/v1.8/...` URLs redirected to a marketing landing page.

Feature is alpha: configuration, helpers, and shipped rules may still change between releases. Owner: [intro](https://docs.crowdsec.net/docs/next/appsec/bot_detection/intro.md). Extract: `.sources/intro.md`.

## Envelope the engine returns to a bouncer

Bot detection adds action `challenge` next to `allow`, `ban`, and `captcha`. `ban` / `captcha` are verdicts the bouncer renders from its own templates. `challenge` is a complete HTTP response the AppSec component generated; the bouncer relays it unchanged. Owner: [challenge protocol](https://docs.crowdsec.net/docs/next/appsec/bot_detection/challenge_protocol.md). Extract: `.sources/challenge_protocol.md`.

JSON field names and Go types (engine `BodyResponse`):

| JSON | Go type | Role |
|---|---|---|
| `action` | `string` | Remediation. For this flow: `"challenge"`. |
| `http_status` | `int` | Status the **browser** must receive. Not the AppSec listener status. |
| `user_body_content` | `string` (`omitempty`) | Body for the browser: challenge HTML, JS asset, or a small JSON status document. |
| `user_headers` | `map[string][]string` (`omitempty`) | Response headers. Each value is a list; replace any header of the same name. A `Content-Security-Policy` is always present on a challenge envelope. |
| `user_cookies` | `[]string` (`omitempty`) | Ready-to-send `Set-Cookie` values. Each entry is one header; never join with commas. |

Owners: [challenge protocol](https://docs.crowdsec.net/docs/next/appsec/bot_detection/challenge_protocol.md); `github.com/crowdsecurity/crowdsec@cc76dbbce40bd2e6a3ce1ba07e3c41d8b462de66:pkg/appsec/appsec.go` (`BodyResponse`). Extracts: `.sources/challenge_protocol.md`, `.sources/appsec.go.md`.

`user_cookies` entries are `http.Cookie.String()` output. Cookie builder defaults: `Path=/`, `SameSite=Lax`. Owner: `github.com/crowdsecurity/crowdsec@cc76dbbce40bd2e6a3ce1ba07e3c41d8b462de66:pkg/appsec/cookie/cookie.go`. Extract: `.sources/cookie.go.md`. Official example: `__crowdsec_challenge=...; Path=/; HttpOnly; SameSite=Lax`. Owner: [challenge protocol](https://docs.crowdsec.net/docs/next/appsec/bot_detection/challenge_protocol.md).

### AppSec listener HTTP status versus `http_status`

Two different status codes:

| AppSec **listener** status (bouncer ↔ engine) | Meaning |
|---|---|
| `200` | Allow. Body `{"action":"allow"}` (base protocol). Bouncer forwards the original request to origin. |
| `403` | Remediation. Body is the JSON envelope (`ban` / `captcha` / `challenge` + extra fields). |
| `401` | Bouncer not authenticated. |
| `500` | Engine error. Bouncer uses its `APPSEC_FAILURE_ACTION`. |

Owners: [WAF / bouncer protocol](https://docs.crowdsec.net/docs/next/appsec/protocol.md); [challenge protocol](https://docs.crowdsec.net/docs/next/appsec/bot_detection/challenge_protocol.md). Extracts: `.sources/protocol.md`, `.sources/challenge_protocol.md`.

A challenge **always** arrives as listener `403` plus `action: "challenge"`. Engine `setChallengeResponse` sets `BouncerHTTPResponseCode` to `BouncerBlockedHTTPCode` (default `403`) while `UserHTTPResponseCode` is the browser status (`200` for the page, assets, and submit JSON; `307` for a pre_eval/post_eval grant redirect). Owners: `github.com/crowdsecurity/crowdsec@cc76dbbce40bd2e6a3ce1ba07e3c41d8b462de66:pkg/appsec/appsec.go` (`setChallengeResponse`, `GenerateResponse`, `Build` defaults). Extract: `.sources/appsec.go.md`.

Browser `http_status` is **not** always `200`. `GrantChallengeCookie()` from `pre_eval` / `post_eval` answers with `307` plus `Location` in `user_headers`. A bouncer that hardcodes `200` breaks that flow. Owner: [challenge protocol](https://docs.crowdsec.net/docs/next/appsec/bot_detection/challenge_protocol.md).

Official bouncer-side default: if `http_status` is absent or zero, treat it as `200`. Owner: [challenge protocol](https://docs.crowdsec.net/docs/next/appsec/bot_detection/challenge_protocol.md).

Engine-side if `UserHTTPResponseCode` is `0` on a `challenge` action: `GenerateResponse` falls through to `UserBlockedHTTPCode` (default `403`), not `200`. That path is for `default_remediation: challenge` with no headers set; the internal challenge-serving paths always set an explicit user code. Owner: `github.com/crowdsecurity/crowdsec@cc76dbbce40bd2e6a3ce1ba07e3c41d8b462de66:pkg/appsec/appsec.go`. Conflict: official tells the bouncer “missing/zero → 200”; this engine version, if it ever emits `http_status: 0` on `challenge`, would have meant blocked-user code. Follow source for what `v1.8.0` emits on real challenge paths (always an explicit code); follow official for the bouncer default when the field is missing.

Bouncer failure table (official):

| AppSec response | Bouncer behaviour |
|---|---|
| `200` | Allow. |
| `403`, `action: challenge`, non-empty `user_body_content` | Serve that response to the browser. |
| `403`, `action: challenge`, empty `user_body_content` | Fail closed — `ban`. |
| `403`, any other action | Apply that action. |
| `403` empty body or invalid JSON | `ban`. |
| `401` / `500` / unexpected | Configured AppSec failure action. |

A `challenge` decision from LAPI / a blocklist has no body; fail closed to `ban`. Restrictiveness when combining remediations: `allow < unknown < captcha < challenge < ban`. Owner: [challenge protocol](https://docs.crowdsec.net/docs/next/appsec/bot_detection/challenge_protocol.md).

## Cookie, callback path, browser submit, granted / exempt

Cookie name: `__crowdsec_challenge`. Owner: `github.com/crowdsecurity/crowdsec@cc76dbbce40bd2e6a3ce1ba07e3c41d8b462de66:pkg/appsec/challenge/challenge.go` (`ChallengeCookieName`); [how it works](https://docs.crowdsec.net/docs/next/appsec/bot_detection/how_it_works.md). Extracts: `.sources/challenge.go.md`, `.sources/how_it_works.md`.

Default TTL `12h`, sealed under the master cookie key (independent of per-epoch signing-key rotation). Owner: [configuration](https://docs.crowdsec.net/docs/next/appsec/bot_detection/configuration.md). Extract: `.sources/configuration.md`.

The bouncer never parses, validates, or mints the cookie. Subsequent requests must forward the browser `Cookie` header to AppSec so a solved challenge becomes `allow`. Owner: [challenge protocol](https://docs.crowdsec.net/docs/next/appsec/bot_detection/challenge_protocol.md).

Internal paths the bouncer must forward to AppSec unmodified, never to origin:

| Path | Method | Purpose |
|---|---|---|
| `/crowdsec-internal/challenge/fpscanner.js` | `GET` | Fingerprinting bundle. |
| `/crowdsec-internal/challenge/pow-worker.js` | `GET` | Proof-of-work worker. |
| `/crowdsec-internal/challenge/submit` | `POST` | PoW result + encrypted fingerprint. |

Official also says forward the prefix `/crowdsec-internal/challenge/*`. Engine constants add `/crowdsec-internal/challenge/challenge.js`; `v1.8.0` does not dispatch that path (constant only). Owners: [challenge protocol](https://docs.crowdsec.net/docs/next/appsec/bot_detection/challenge_protocol.md); `github.com/crowdsecurity/crowdsec@cc76dbbce40bd2e6a3ce1ba07e3c41d8b462de66:pkg/appsec/challenge/challenge.go`, `pkg/appsec/appsec.go` (path dispatch). Follow source for which paths this version serves; follow official for the wildcard the bouncer must not send to origin.

Browser solve: challenge page loads fpscanner + PoW/crypto + per-epoch key module; the browser POSTs the result to `/crowdsec-internal/challenge/submit`. The POST body must be relayed as POST per the base protocol. Owner: [how it works](https://docs.crowdsec.net/docs/next/appsec/bot_detection/how_it_works.md); [challenge protocol](https://docs.crowdsec.net/docs/next/appsec/bot_detection/challenge_protocol.md).

Submit (and the JS assets) also come back as listener `403` + `action: challenge` + browser `http_status: 200`. A solved challenge is **not** `allow` on that hop. Submit JSON bodies:

| `user_body_content` | Meaning |
|---|---|
| `{"status":"ok"}` | Proof accepted. `user_cookies` carries `__crowdsec_challenge`. |
| `{"status":"failed"}` | Bad PoW / ticket / HMAC / expired epoch. No cookie. Client may retry. |
| `{"status":"rejected"}` | Proof valid, but `on_challenge_submit` called `RejectSubmission()`. No cookie. Terminal UI, no retry. Server reason is logged, not echoed. |

Owners: [challenge protocol](https://docs.crowdsec.net/docs/next/appsec/bot_detection/challenge_protocol.md); `github.com/crowdsecurity/crowdsec@cc76dbbce40bd2e6a3ce1ba07e3c41d8b462de66:pkg/appsec/appsec.go` (`bodyChallengeOK` / `Failed` / `Rejected`, submit handler). Extract: `.sources/appsec.go.md`.

### Granted versus exempt

Metrics funnel: `requested` → `submitted` → `accepted` (`solved` or `granted`) or `rejected` (`protocol`, `submission`, or `cookie`). `Exempt` is a separate column: requests an exclusion config skipped. Owner: [enable](https://docs.crowdsec.net/docs/next/appsec/bot_detection/enable.md). Extract: `.sources/enable.md`.

| Term | What it is |
|---|---|
| **solved** | Cookie issued after a valid browser submission (`kind="solved"`). |
| **granted** | Cookie minted by `GrantChallengeCookie(reason, ttl?)` without a real solve (`kind="granted"`, reason label = operator string). `pre_eval`/`post_eval`: 307 + `Location` + cookie. `on_challenge_submit`: cookie attached to the existing submit JSON (no 307). |
| **exempt** | `ExemptFromChallenge(reason)` on the **current request only**. No cookie. `SendChallenge()` becomes a no-op. Used for verified known bots and path exclusions. Counted on `cs_appsec_challenge_exempt_total`. |

Owners: [hooks](https://docs.crowdsec.net/docs/next/appsec/bot_detection/hooks.md); `github.com/crowdsecurity/crowdsec@cc76dbbce40bd2e6a3ce1ba07e3c41d8b462de66:pkg/metrics/acquisition_appsec.go`; `pkg/appsec/appsec.go` (`GrantChallengeCookie`, `GrantAllowlistCookieInline`); `pkg/appsec/waf_helpers.go` (submit-phase helper routes to inline). Extracts: `.sources/hooks.md`, `.sources/acquisition_appsec.go.md`, `.sources/appsec.go.md`, `.sources/waf_helpers.go.md`.

Why 307 on grant: `GenerateResponse` only serializes `user_cookies` on `action: challenge`, so a plain `allow` would drop `Set-Cookie`. Owner: `github.com/crowdsecurity/crowdsec@cc76dbbce40bd2e6a3ce1ba07e3c41d8b462de66:pkg/appsec/appsec.go`.

## Hub collections and acquis

Install one bundle:

```
cscli collections install crowdsecurity/appsec-bot-challenge
```

Variants: `crowdsecurity/appsec-bot-challenge-strict` (reject `>= 45`), `crowdsecurity/appsec-bot-challenge-permissive` (reject `>= 100`). Default balanced rejects `>= 75`. Do not install several: a wildcard loads every installed threshold config and the strictest wins. Owners: [enable](https://docs.crowdsec.net/docs/next/appsec/bot_detection/enable.md); hub collections `github.com/crowdsecurity/hub@31d852a3737c12ee095bee18ebc2942fb6707e8d:collections/crowdsecurity/appsec-bot-challenge.yaml` (and `-strict.yaml`, `-permissive.yaml`). Extracts: `.sources/enable.md`, `.sources/appsec-bot-challenge.yaml.md`. Hub PR that landed them: [crowdsecurity/hub#1826](https://github.com/crowdsecurity/hub/pull/1826).

AppSec acquisition (typically `/etc/crowdsec/acquis.d/appsec.yaml`):

```yaml
listen_addr: 127.0.0.1:7422
appsec_configs:
  - crowdsecurity/appsec-default
  - crowdsecurity/appsec-bot-*
labels:
  type: appsec
```

The wildcard matches **installed** appsec-configs only (scoring engine, its threshold, every exclusion). A broader `crowdsecurity/*` also works. Custom overlays in another namespace are not matched by `crowdsecurity/appsec-bot-*` and must be listed by name. Owner: [enable](https://docs.crowdsec.net/docs/next/appsec/bot_detection/enable.md). Docker `COLLECTIONS` is the usual way to install the hub collection at container start; it does not replace `appsec_configs:` in acquis.

## Unsupported bouncers silently refuse every client

Official warning: check that the bouncer supports bot detection first. Enabling it behind one that does not “leads to unexpected behavior, most likely silently refusing every client.” Owner: [enable](https://docs.crowdsec.net/docs/next/appsec/bot_detection/enable.md).

Observed on this product’s released plugin (`v1.7.1`) with CrowdSec `1.8.0`: AppSec issues the challenge, the plugin closes the AppSec write (`broken pipe`), the browser never gets the page, every request is `403`. Owner: [maxlerebourg/crowdsec-bouncer-traefik-plugin#389](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/389) (ticket; reproduces the official warning). Extract: `.sources/issue-389.md`.

## Traefik bouncer: new option or not

Protocol: no new CrowdSec-side plugin key. Need AppSec enabled (existing `crowdsecAppsecEnabled` + AppSec host) and `/crowdsec-internal/challenge/*` routed through the **same** CrowdSec middleware as the protected app, so the bouncer forwards those paths to AppSec instead of origin. Owners: [challenge protocol](https://docs.crowdsec.net/docs/next/appsec/bot_detection/challenge_protocol.md); PR author on [maxlerebourg/crowdsec-bouncer-traefik-plugin#343](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/343) (CrowdSec staff). Extract: `.sources/pr-343.md`.

PR 343 is the bouncer-side parse of `action` / `http_status` / `user_body_content` / `user_cookies` / `user_headers`. It was open on 2026-09-05; released plugin `v1.7.1` does not relay the envelope. Owner: [#343](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/343); maintainer on [#389](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/389).

Conflict on “Traefik is compatible”: [intro](https://docs.crowdsec.net/docs/next/appsec/bot_detection/intro.md) lists Traefik among compatible bouncers. CrowdSec’s 1.8 blog says nginx/openresty are compatible and they are “waiting on traefik and envoy releases.” Owner: [CrowdSec 1.8 blog](https://www.crowdsec.net/blog/crowdsec-1-8-waf-bot-detection-kubernetes). Extract: `.sources/crowdsec-1-8-blog.md`. Follow the blog + open PR + maintainer on #389 for this product’s released plugin; treat the intro list as stale.

Weaker comment on #343: set existing `crowdsecAppsecUnreadableBodyBlock: false` so POST submit bodies are not dropped. That is not a new option and is not in official protocol. Official requires forwarding the POST body; keep the comment as operational colour only. Owner: comment on [#343](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/343#issuecomment-5516259815). Extract: `.sources/pr-343.md`.

## Docker image tag

First **GA** image that ships the engine feature: `crowdsecurity/crowdsec:v1.8.0` (Alpine `{version}` flavor). Tag exists on Docker Hub (pushed 2026-09-01). GitHub release `v1.8.0` (2026-08-31) is the first stable engine release that documents bot detection (`#4268` WAF challenge mode). Flavors: `v1.8.0`, `v1.8.0-slim`, `v1.8.0-debian`. Earlier RC images `v1.8.0-rc1` / `v1.8.0-rc2` existed; `v1.8.1` is later, not the first. Not “later than 1.8.0” for GA.

Owners: [v1.8.0 release](https://github.com/crowdsecurity/crowdsec/releases/tag/v1.8.0); Docker README flavor `crowdsecurity/crowdsec:{version}` at `github.com/crowdsecurity/crowdsec@cc76dbbce40bd2e6a3ce1ba07e3c41d8b462de66:build/docker/README.md`; Docker Hub tag `v1.8.0`. Extracts: `.sources/v1.8.0-release.md`, `.sources/docker-readme.md`, `.sources/dockerhub-v1.8.0.md`.

Hub collections are not baked into that image; install `crowdsecurity/appsec-bot-challenge` (or a variant) via `cscli` / `COLLECTIONS`, then list `crowdsecurity/appsec-bot-*` in acquis. Docs for the feature were merged via [crowdsecurity/crowdsec-docs#1099](https://github.com/crowdsecurity/crowdsec-docs/pull/1099) (into `1.8.0-release`). #1100 (challenge protocol draft) was closed unmerged; the live protocol page is the next-docs challenge protocol above.

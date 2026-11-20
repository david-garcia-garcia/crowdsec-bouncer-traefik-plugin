# Source (issueHost: local)

Caller: chat request, 2026-11-20.

## Human text

> usa opd-workflow para proponer un PR con nuestra nueva opcion de bypassCaptcha, segúrate de que qued abien documento en el readme en qué casos funciona y en cuales no, y con respecto a los de las rutas, aplica le regex tal cual porque traefik ya nos protege contra el path traversal en la url

## Chat context the ask refers to

The details of the incident that started the conversation are private and are not copied here. The generic shape:

- A machine-to-machine API client called a public route protected by this plugin. A CrowdSec decision with a wide scope (a whole AS) and type `captcha` was active. The client matched the scope, so the plugin answered the API call with the captcha HTML page and HTTP 200. The client cannot solve a captcha and took the HTML for an API response.
- The caller asked what the plugin offers today for API routes. Answer given in chat: `bouncerClientTrustedIps` (skips everything for an address), `bouncerOriginBasedDecisionRemap` with `captcha: pass` (per router, per origin), and a `bypassLapi` action rule on the API path (also skips bans). None of them says "on this path, never a captcha, bans still apply".
- The caller then proposed an action for `bouncerActionRules` that downgrades a captcha to a pass on matching requests while bans keep applying. The assistant proposed the token name `bypassCaptcha` and this behaviour per captcha source, and the caller then asked for the PR ("nuestra nueva opcion de bypassCaptcha"):

| Captcha source | With `bypassCaptcha` |
|---|---|
| CrowdSec decision of type `captcha` | request passes |
| AppSec `captcha` verdict | request passes |
| LAPI or AppSec failure action `captcha` | request passes |
| A ban that `bouncerOriginBasedDecisionRemap` softens to a captcha | stays a ban (a ban must not become a pass in two hops) |
| A `captcha` action in the same rule | rejected at validation |
| A `captcha` action in another rule that matches the same request | `bypassCaptcha` wins |
| AppSec bot-detection `challenge` | not covered by the token |

- Path rules. The assistant proposed that `bypassCaptcha` follow the same single-reading path guard as the `bypass*` tokens (`httprule.SingleReadingPath`). The caller decided against it in the ask above: the path regex applies as written, because Traefik already protects against path traversal in the URL.
- The assistant read the Traefik documentation in chat (request path page, entry points reference, v3 migration guide) and reported: Traefik decodes unreserved percent-encoded characters and removes `.` and `..` segments by default (`sanitizePath`), and by default does not reject encoded reserved characters such as `%2F`. What a middleware receives was inferred from the documented order, not measured.

## Documentation ask

The README must say clearly in which cases `bypassCaptcha` works and in which it does not.

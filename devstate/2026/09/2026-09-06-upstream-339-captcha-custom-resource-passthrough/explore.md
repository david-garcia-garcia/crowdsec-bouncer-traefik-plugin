# Explore

## Concepts

Custom captcha (`captchaProvider=custom`) loads the widget JS from `CaptchaCustomJsURL` and, for providers like wicketkeeper, fetches a challenge from a second same-host path (`/v0/challenge`). Those paths are origin resources. Ban and captcha HTML stay on the plugin.

```
captcha-flagged request
        │
        ▼
 ┌──────────────────────┐
 │ kind == captcha      │
 └──────────┬───────────┘
            │
    path is JS or challenge URL?
            │
     yes ───┴─── no
      │           │
      ▼           ▼
  next (origin)  Check() grace?
                  │
            yes ──┴── no
             │         │
             ▼         ▼
           next     captcha HTML

ban kind: never this pass-through
```

Client address is already on `clientRequest.remoteIP` (`pkg/ip.GetRemoteIP`). Pass-through does not re-parse `RemoteAddr`.

`pkg/captcha.Client` owns the custom JS/validate URLs today. Challenge URL and “does this request match a custom resource path?” belong there. `handleRemediationServeHTTP` asks that owner, then `handleNextServeHTTP` (existing pass path, AppSec still runs if enabled).

No Traefik process-lifetime change. No reclaim / `sync.Once`.

## Decisions

- Add `CaptchaCustomChallengeURL` (`json:"captchaCustomChallengeUrl,omitempty"`) next to the other custom captcha fields.
- Pass-through only when remediation kind is captcha, provider is custom, and the request path equals the path of `CaptchaCustomJsURL` or `CaptchaCustomChallengeURL`. Ban never matches.
- Path-only exact match: parse each configured value as a URL; compare `url.Path` to `req.URL.Path`; ignore scheme, host, query, fragment. Config `http://captcha.localhost:8000/fast.js` matches `GET /fast.js` on any Host. Empty challenge URL: no challenge match. Invalid parse: treat the raw string as the path if it starts with `/`, else no match.
- Challenge URL is optional at validate time so existing custom configs still boot. Operators who need challenge pass-through set the key.
- Matching custom-resource requests pass through for every method, including HEAD, so `/fast.js` is not banned by the existing captcha-HEAD→ban fallback. Non-matching captcha HEAD still bans (`TestCaptchaMethodBasedLogic`).
- Put `ChallengeURL` on the captcha template map (sibling of `FrontendJS`). Update `examples/custom-captcha` README + `captcha.html` + compose label. Do not change the default `captcha.html` (CDN providers do not need it).
- Unit tests on bouncer: captcha-flagged JS/challenge path → next; other path → captcha HTML; ban-flagged same path → ban. Config test: custom provider still valid without challenge URL.
- Not reproduced on a live wicketkeeper stack this run. Grounded from `pkg/bouncer/bouncer.go` captcha branch, missing config key, and example HTML that points at `/v0/challenge` without pass-through.

## Open questions

- Q: What URL matching semantics apply (path vs full URL vs prefix)?
  Decision: assumed — exact path of the parsed config URL vs `req.URL.Path`; ignore host/query; no prefix. Absolute example URLs still match the browser path on the protected host.
  By: explore

- Q: Is `CaptchaCustomChallengeURL` required when custom provider is enabled?
  Decision: assumed — optional. Empty means no challenge pass-through. Requiring it would reject existing Traefik labels.
  By: explore

- Q: Should pass-through apply on HEAD (captcha branch currently skips HEAD and bans)?
  Decision: assumed — yes for matching custom resource paths only. Other captcha HEAD stays ban.
  By: explore

- Q: Who already owns the client address for this pass-through?
  Decision: resolved — `pkg/ip.GetRemoteIP` folded into `clientRequest.remoteIP`. Reuse that. Do not parse `RemoteAddr` again.
  By: explore

- Q: Should custom-resource pass-through skip AppSec?
  Decision: assumed — no. Use `handleNextServeHTTP` so AppSec still runs if enabled. Ticket asked origin reach, not an AppSec bypass.
  By: explore

- Q: Should the captcha HTML template learn the challenge URL, or only pass-through?
  Decision: assumed — put `ChallengeURL` in the execute map and wire the custom-captcha example. Default `captcha.html` unchanged.
  By: explore

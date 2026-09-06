# upstream#353

- title: [FEATURE] Linking solved CAPTCHAs to IP + cookie
- state: OPEN
- url: https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/353
- created: 2026-07-15T12:32:54Z
- updated: 2026-07-27T19:42:34Z
- labels: (none)

## Body

**Is your feature request related to a problem? Please describe.** 🐛
If a user solves the CAPTCHA, only the IP address is recorded in the cache. Multiple users may share the same IP address; if one solves it, access is granted to all of them.
Additionally, a single user can solve the CAPTCHA and subsequently use automated tools from that IP address for the duration specified in `CaptchaGracePeriodSeconds`.

**Describe the solution you'd like** ✨
I would like to achieve the same behavior as Cloudflare. Cloudflare caches not only the IP address but also adds a cookie; if the cookie doesn't match, the CAPTCHA is not considered solved for that IP address.


**UPD**
You could also tie the user agent to the session for greater reliability. You can even add a protocol.
In other words, using a combination of `IP+cookie+useragent+protocol` (protocol HTTP/1.1, HTTP/2.0, HTTP/3.0) increases accuracy—for instance, in case a cookie is copied into an automated system. All the listed items are always the same within a single session.
Of course, like any other measure, this isn't a foolproof defense, but it does make things more difficult for automated programs.

---

# Assessment: upstream#353

- relevant: yes
- kind: feature
- affected: yes
- status: present-unfixed
- proof: none
- recommended-action: fix
- slug: 2026-09-06-upstream-353-captcha-session-cookie
- rationale: Our captcha remediation still keys the grace-period cache only on client IP. `pkg/captcha/captcha.go` writes and reads `{remoteIP}_captcha` in `ServeHTTP` and `Check`; `pkg/bouncer/bouncer.go` passes only `req.remoteIP` into those calls. There is no Set-Cookie on solve, no cookie check on subsequent requests, and no user-agent or protocol binding. AppSec bot-detection challenge cookies (`pkg/appsec`) are a separate relay path and do not change plugin-native captcha grace behavior. The shared-IP and post-solve automation gaps described upstream therefore remain on master.

## Evidence
- current: pkg/captcha/captcha.go, pkg/bouncer/bouncer.go
- tests: none

# upstream#357

- title: [FEATURE] Add support for "captcha"-type solutions to the AppSec module.
- state: OPEN
- url: https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/357
- created: 2026-07-21T15:12:32Z
- updated: 2026-07-21T15:12:32Z
- labels: (none)

## Body

**Is your feature request related to a problem? Please describe.** 🐛
Currently, it is not possible to use the "captcha" solution for the appsec module—for instance, to instantly display a CAPTCHA if a request meets certain conditions.
As I understand it, Bouncer currently reads only the response code.


**Describe the solution you'd like** ✨
Implement reading the response body from crowdsec, namely the `action` parameter.
[Example from the official crowdsec documentation WAF / Bouncer Communication Protocol](https://docs.crowdsec.net/docs/appsec/protocol#response-code):
```json
{"action" : "captcha", "http_status": 403}
```


**Additional context**
If the question arises of how—or whether—to cache solved CAPTCHAs, my personal opinion remains the same: cache them in exactly the same way.
An option could also be added to select the caching mode for solved CAPTCHAs.

I hope I’ve conveyed my thoughts clearly.
This might be a duplicate, but none of the discussions I’ve reviewed contain a clear request for [this functionality](https://docs.crowdsec.net/docs/appsec/protocol#response-code) to be implemented (`action" : "captcha"`).

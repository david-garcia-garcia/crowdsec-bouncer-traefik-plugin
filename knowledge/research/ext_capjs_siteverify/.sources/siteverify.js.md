---
url: https://github.com/tiagozip/cap/blob/e02138579482c711ee0bb79c7be3486fe0bf3e84/standalone/src/siteverify.js
title: Cap Standalone siteverify handler
ref: github.com/tiagozip/cap@e02138579482c711ee0bb79c7be3486fe0bf3e84:standalone/src/siteverify.js
fetched: 2026-09-06
authority: source
---

POST /:siteKey?/siteverify

Destructures body: { secret, response } (JSON body via Elysia).

No remoteip handling in handler.

Requires secret and response; 400 if missing.

Valid secret verified against stored secretHash for site key.

Token single-use via db.getdel on token:${response}.

Success return: { success: true }

Failure returns: { success: false, error: "..." } with 400/403/404.

Site key from path param or first segment of response token (colon-delimited, expects 3 parts).

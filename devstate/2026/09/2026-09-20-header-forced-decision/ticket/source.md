Title: Config-gated incoming header forces ban or captcha without stream lookup

A feature enabled through config: when a special incoming header in the request appears (example name X-Crowdsec-Decision) it can have values b or c (ban or captcha only). Such a decision is applied without even querying the stream. Purpose: other middlewares can decide to CAPTCHA a client. Careful because captcha gate can also be passed even if we receive c — the middleware will still see the c header, but because the user gated OK the captcha, the request can go through.

---
url: https://docs.crowdsec.net/u/bouncers/haproxy_spoa.md
title: HAProxy SPOA
fetched: 2026-09-25
authority: official
---

Captcha HTML return: HTTP 200, content-type text/html; charset=utf-8, hdr Cache-Control "no-cache, no-store", lf-file captcha.html.

Ban HTML returns: HTTP 403, same Cache-Control "no-cache, no-store", lf-file ban.html / ban-with-contact.html.

Plain-text fallbacks for captcha and ban use the same Cache-Control "no-cache, no-store".

Successful captcha validation is a 302 redirect, not that return header.

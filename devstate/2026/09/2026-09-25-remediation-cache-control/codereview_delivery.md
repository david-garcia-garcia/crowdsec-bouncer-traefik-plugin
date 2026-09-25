# Delivery

## Motivation

Captcha challenge HTML is the 200 this plugin writes on the original URL: Content-Type from the template, optional remediation header, then the template. That path does not Set-Cookie; the gate cookie is only on Pass before the 302. Ban HTML is the same pattern from the ban writer: Content-Type, optional remediation header, then the remediation status. AppSec challenge relay already copies engine `user_headers`, including `Cache-Control` when the engine sends it.

A CDN in front of Traefik stored that captcha HTML — HTTP 200 on the original URL, Content-Type only, no Set-Cookie. After the captcha decision was cleared, the CDN kept serving the stored page. Both writers omit `Cache-Control`. Ban HTML is the same cacheable remediation body with no cache header.

Left alone, clearing a captcha decision does not clear the cached HTML. Visitors keep solving a challenge CrowdSec has already dropped. Ban pages can stay stored the same way. CDN cache keys and TTLs are not in this tree; the plugin sent nothing a cache is required to treat as unstoreable.

Priority: P2 — real end-user pain, with a workaround or limited blast radius

## Implementation

On each writer this plugin owns, set `Cache-Control: no-cache, no-store` before WriteHeader. Challenge HTML gets it on the 200 path. The Pass 302 and the second-tab `WriteSolvedRedirect` set the same value, so a proxy cannot store a redirect to the same URL. The ban writer sets it once, so HEAD and nil-template bans carry it the same way Content-Type already does. The string is exactly that value — HAProxy SPOA captcha/ban returns and the AppSec challenge protocol example, no extra directives. AppSec envelope relay stays unchanged. Challenge 200, both solve 302s, and ban header tests assert the header.

## What this changes
**Operators.** No new plugin or Traefik key; after deploy, captcha challenge 200s, both solve redirects, and ban remediations send `Cache-Control: no-cache, no-store`.
**Admin users.** None.
**Developers.** Challenge HTML at 200, the Pass 302, `WriteSolvedRedirect`, and ban responses must set `Cache-Control: no-cache, no-store` before WriteHeader.
**End users.** A cache in front of Traefik that honors Cache-Control should stop serving a stored captcha page or a stored solve redirect after the decision is cleared; ban HTML should not stay stored either.

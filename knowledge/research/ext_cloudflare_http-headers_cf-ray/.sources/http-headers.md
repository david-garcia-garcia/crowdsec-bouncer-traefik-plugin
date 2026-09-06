---
url: https://developers.cloudflare.com/fundamentals/reference/http-headers/#cf-ray
title: Cloudflare HTTP headers — Cf-Ray
fetched: 2026-09-06
authority: official
---

Cf-Ray (Ray ID) is a hashed value that encodes information about the data center and the visitor's request.

Example: `Cf-Ray: 230b030023ae2822-SJC`

The Cf-Ray header identifies the data center processing the request when displayed as a response header. This is represented by a three-letter code corresponding to the data center's location.

The Cf-Ray header is also sent to upstream origins and may be modified to reflect the connecting data center (Argo Smart Routing or Argo Tiered Caching). In those cases the three-letter code is the colo connecting to origin, not the ingress colo.

Response: the Cf-Ray value returned to the visitor is the same Cf-Ray value that was sent to the origin server.

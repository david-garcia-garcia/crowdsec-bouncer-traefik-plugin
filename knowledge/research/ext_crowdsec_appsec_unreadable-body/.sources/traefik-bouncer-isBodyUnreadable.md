---
ref: github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin@04d928872df12bdb9d953b2d92948e0b89692d6a:bouncer.go
title: isBodyUnreadable
fetched: 2026-09-06
authority: source
---

HTTP/2 or HTTP/3 without Content-Length (bidirectional gRPC stream) — body never reaches EOF; io.ReadAll would block.

func isBodyUnreadable(httpReq *http.Request) bool {
  return httpReq.Body != nil && httpReq.Body != http.NoBody && httpReq.ProtoMajor >= 2 && httpReq.ContentLength < 0
}

Mirrors lua-cs-bouncer behavior.

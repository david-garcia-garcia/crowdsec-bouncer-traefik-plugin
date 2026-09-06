---
ref: github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin@04d928872df12bdb9d953b2d92948e0b89692d6a:bouncer.go
title: appsecQuery unreadable branch
fetched: 2026-09-06
authority: source
---

case isBodyUnreadable(httpReq):
  if bouncer.appsecUnreadableBodyBlock && isMethodWithBody(httpReq.Method) {
    return errors.New("appsecQuery:unreadableBody dropped")
  }
  req, _ = http.NewRequest(http.MethodGet, routeURL.String(), nil)

isMethodWithBody: POST, PUT, PATCH only.

Test comment: mirrors reference APPSEC_DROP_UNREADABLE_BODY option.

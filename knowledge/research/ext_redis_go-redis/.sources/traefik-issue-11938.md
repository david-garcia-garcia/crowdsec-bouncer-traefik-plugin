---
url: https://github.com/traefik/traefik/issues/11938
title: Ability to use yaegi's syscall.Symbols
fetched: 2026-09-05
authority: vendor
---

Issue author david-garcia-garcia: official Redis Go library cannot be used in Traefik middlewares without syscall; Crowdsec bouncer named.
orbsfoc 2025-09-11: hand-crafted Redis client because go-redis v9 is not supported.
orbsfoc 2025-10-15: with syscall enabled, a go-redis plugin loads, then panics reflect.Value.Interface: cannot return value obtained from unexported field or method.
david-garcia-garcia 2025-10-20: did not do a full Redis integration; may be Yaegi.
orbsfoc 2025-10-20: Yaegi limitation — modules that use reflection.

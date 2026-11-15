---
url: https://github.com/crowdsecurity/crowdsec/blob/3d369d64eb3e9ba770ed39aedc83ffd3170aef4c/pkg/appsec/patcher.go
title: pkg/appsec/patcher.go RateLimit call collection
fetched: 2026-11-14
authority: source
ref: github.com/crowdsecurity/crowdsec@3d369d64eb3e9ba770ed39aedc83ffd3170aef4c:pkg/appsec/patcher.go
---

An AST walk over every compiled hook collects each `RateLimit()` call by key, "so a bad one fails the config load".

- The hidden first argument (`_request_ctx`, injected by `expr.WithContext`) is skipped; the author writes `RateLimit("key", "N/u")` or `RateLimit("key", "N/u", source)`.
- key must be a string literal, else `RateLimit: key must be a string literal`.
- limit must be a string literal, then parsed by `parseRateLimitSpec`.
- duplicate key -> `RateLimit("k"): key is used by more than one call`.

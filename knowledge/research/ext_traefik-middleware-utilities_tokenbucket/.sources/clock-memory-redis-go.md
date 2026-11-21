---
url: https://github.com/david-garcia-garcia/traefik-middleware-utilities/blob/42e6a1a967155318023c4defe491d1d423e165b6/tokenbucket/clock.go
title: tokenbucket/clock.go, memory.go, redis.go
fetched: 2026-11-20
authority: source
ref: github.com/david-garcia-garcia/traefik-middleware-utilities@42e6a1a967155318023c4defe491d1d423e165b6:tokenbucket/
---

validateClock: rate <= 0 || NaN || Inf → errRate; burst < 1; maxDelay < 0; ttl < 1s || ttl % 1s != 0.

consumeOne(tokens, last, limitPerMicro, burst, nowMicro, maxDelayMicro): refill from elapsed, cap at burst, tokens--; if tokens < 0 → waitMicro = -tokens/limitPerMicro; refund (tokens++) when waitMicro > float64(maxDelayMicro). Persist last = max(previous last, now).

waitDuration(waitMicro) = time.Duration(waitMicro * 1µs), 0 when waitMicro <= 0. allowedFromWait(wait, maxDelay) = wait <= maxDelay.

Memory.Allow: lock, now after lock, new key = full bucket; consumeOne(..., maxDelay.Microseconds()); return allowedFromWait(waitDuration(waitMicro), maxDelay), wait, nil. maxMemorySources = 65536; dropOne deletes an arbitrary live key at the cap.

Redis.Allow: EVAL allowScript with ARGV limitPerMicro, burst, ttlSeconds, nowMicro, maxDelay.Microseconds(); non-finite wait → errEvalWait; return allowedFromWait(waitDuration(waitMicro), maxDelay).

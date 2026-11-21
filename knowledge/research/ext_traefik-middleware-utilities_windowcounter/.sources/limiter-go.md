---
url: https://github.com/david-garcia-garcia/traefik-middleware-utilities/blob/42e6a1a967155318023c4defe491d1d423e165b6/windowcounter/limiter.go
title: windowcounter/limiter.go
fetched: 2026-11-20
authority: source
ref: github.com/david-garcia-garcia/traefik-middleware-utilities@42e6a1a967155318023c4defe491d1d423e165b6:windowcounter/limiter.go
---

New(redis, syncRate): nil redis and negative syncRate fail; 0 < syncRate < 20ms floors to 20ms; syncRate > 0 arms a time.AfterFunc flush timer (not go+select: Yaegi v0.16.1 _select hang).

slidingAt: window < 1s or window % 1s != 0 → error. windowStart = now.Unix()/windowSec*windowSec. weight = 1 - elapsed/window. ttl = 2*windowSec. Keys: key + ":" + windowStart.

takeExact: Incr(current); if current == 1 → Expire(current, ttl) (error returned, never retried later); Get(previous); estimated = current + previous*weight; allowed = estimated <= limit.

takeBuffered: windowLocked GETs current on first sight or when localDelta == 0; bufferedCountLocked returns memory for a previous key already in l.windows (no GET); localDelta++; returns (estimated <= limit, estimated, bufferedOutageErrorLocked()).

bufferedOutageErrorLocked: returns lastFlushErr if set; else, if Redis was not contacted within syncRate, flush, then probe GET one key; error on failure.

flushScript: exists → incrby → expireat if new. One EVAL per dirty key per tick, without l.mu held.

---
url: https://www.dragonflydb.io/docs/command-reference/strings/mget
title: Redis MGET Command (Documentation)
fetched: 2026-09-05
authority: official
---

MGET key [key ...]. Returns an array in request order. Missing or expired key → nil for that slot, no error. Works with binary strings. Example combines SET … EX 1 with later MGET showing nil after expiry.

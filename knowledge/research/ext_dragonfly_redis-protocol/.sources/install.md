---
url: https://www.dragonflydb.io/install
title: Dragonfly - Install
fetched: 2026-09-05
authority: official
---

Local run via Docker: docker run --network=host --ulimit memlock=-1 docker.dragonflydb.io/dragonflydb/dragonfly

Once installed, Dragonfly will respond to both HTTP and RESP (Redis Serialization Protocol) requests out of the box. Test with any Redis-compatible client. Example redis-cli -p 6379; SET hello world; GET hello.

Claims fully compatible with the Redis ecosystem and requires no code changes to implement.

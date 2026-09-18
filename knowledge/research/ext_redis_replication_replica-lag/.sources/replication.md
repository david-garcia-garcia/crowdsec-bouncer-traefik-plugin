---
url: https://redis.io/docs/latest/operate/oss_and_stack/management/replication/
title: Redis replication
fetched: 2026-09-18
authority: official
---

Leader-follower replication. Replicas reconnect and attempt to be exact copies of the master.

When well-connected, the master sends a stream of commands that replicate writes, expires, evictions, and other dataset changes.

Redis uses asynchronous replication by default. Replicas asynchronously acknowledge the amount of data they receive. The master does not wait every time for a command to be processed by the replicas.

Synchronous replication of certain data can be requested with WAIT. WAIT ensures a number of acknowledged copies; it does not make a Redis set a CP system with strong consistency.

Important facts include: asynchronous replication with asynchronous replica-to-master acks; replicas can accept connections from other replicas; replication can be used for read-only query scalability.

During initial synchronization a replica may handle queries using the old dataset if configured; otherwise it can return an error while the stream is down.

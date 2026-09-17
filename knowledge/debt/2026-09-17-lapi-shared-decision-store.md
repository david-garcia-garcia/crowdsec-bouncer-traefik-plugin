# Shared LAPI decision store reclaim entry

IssueKey: 2026-09-17-lapi-transport-router-policy
Size: large
Action: note

## Why this follow-up
In-memory cache ignores instance prefix so each `Client` keeps its own map; the stream `updated` lease in `client_stream.go` is not shared across local cache backends.

## Why it was not taken
Requires reclaim keyed by cursor plus store parameters, atomic Redis lease (EVAL), and shared local cache semantics — blast radius beyond transport and per-router policy split.

## Risks
Stream freshness and cache coherence stay per-client in memory-only deployments until this lands.

## Context
Current: `pkg/cache/cache.go:183-184`, `pkg/lapi/client_stream.go:66-81`, `cache.Client.Close()` at `cache.go:251`.

# In-memory Range tree, Redis still source of truth

Slug: performance-ip-range
IssueKey: 2026-09-05-performance-ip-range

## Problem

Stream/alone Range matching walks range-index (newline cidr=remediation blob) on every request. Redis MGETs that whole blob with the client IP. Cost is O(n) CIDR tests; the common path is a miss (allowed request), so the full list is always walked.

Throwaway bench (this tree, 2026-09-05): miss at n=64 ≈ 6.5µs, n=512 ≈ 53µs, n=4096 ≈ 573µs per lookup. pkg/iplookup membership stays ~25–75ns.

Trusted-IP already uses pkg/iplookup. Range was explicitly left as a linear walk (core_plugin_ip_radix-lookup, core_plugin_decisionscope Language Avoid: radix tree on the request path).

## Non-goals

Do not poll LAPI from every pod.
Do not MGET range-index on the request path.
Do not put Range membership in pkg/ip.Checker (trusted hops ≠ remediations).
Do not geolocate. Client IP stays pkg/ip.GetRemoteIP.
Do not add sync.Once / package globals. Tree lives on CrowdsecConnection (reclaim value).
Do not change live/none: those still expand Range via LAPI ?ip= and skip range-index.

## Current sync (do not break)

In-process: reclaim.Open → one CrowdsecConnection → one stream ticker.

Cross-pod, Redis on: each pod still ticks. handleStreamCache GETs cache key "updated". Hit → skip LAPI. Miss → SET "updated" TTL UpdateIntervalSeconds-1 (min 1), then GET /v1/decisions/stream, write IP keys + ApplyRangeBatch to Redis.

This is best-effort (GET then SET, not SET NX). Followers never see stream.New / stream.Deleted. They stay correct today because ServeHTTP reads Redis.

LAPI: cursor is on the bouncer row, not the API key string. Same key + same client IP → shared cursor. Same key + new IP → new row (name@<ip>). Facts: knowledge/research/ext_crowdsec_lapi_stream-cursor/.

No Redis: "updated" is per-process memory. Every pod polls LAPI. Each can build Range from the stream.

## Design

Keep range-index as the durable shared document (Redis or local map). Add an in-process radix used only on the request path in stream/alone.

### Where it lives

On CrowdsecConnection, next to cacheClient. Rebuild under that connection’s ticker. Close() drops it with the connection.

### Request path

LookupCachedRemediation:

GetMany without RangeIndexKey.
Range hit = local tree, not MatchRangeFromIndex on a blob.
Ban still wins over captcha across Ip / Range / header scopes (PreferRemediation).
Empty tree + no Range decisions = miss (same as empty blob today).

### Who updates the tree (every pod’s ticker)

handleStreamCache already runs on every pod. That is the only place that decides “is my tree current?”

Lease miss (this pod polls LAPI): apply stream, ApplyRangeBatch as today, then rebuild the local tree from the blob just written (or from the same upserts/removals).

Lease hit (this pod skips LAPI): still GET range-index (optional: a small generation/hash key written next to the blob). If changed vs last hydrate → rebuild. If unchanged → keep the tree.

Memory cache (no Redis): lease is local; this pod always polls; rebuild from stream/blob after apply. No follower hydrate.

New connection: tree empty until first tick (or one hydrate at startStream before serving). Prefer hydrate at stream start so the first requests are not a Range miss.

### Tree shape (reuse, do not overfit iplookup)

pkg/iplookup.Helper is boolean membership + longest prefix. No payload, no delete. Spec for Range is ban wins if several CIDRs contain the IP, not longest-prefix-wins.

Do not use one LPM tree with a single remediation. That would let a captcha /24 hide a ban /8.

Smallest reuse: two Helpers on the connection (ban CIDRs, captcha CIDRs). Lookup: if ban tree contains IP → ban; else if captcha tree contains → captcha.

Deletes / upserts: rebuild from the blob, do not add DeleteCIDR unless a later change needs incremental updates. Typical Range cardinality is small; rebuild on tick is enough.

IPv4/IPv6 stay separate family roots (already true in in-tree iplookup).

### Redis keys

Keep range-index format (cidr=remediation lines, TTL 365d). Optional extra key range-index-gen (monotonic or hash) so followers can skip downloading a large blob when unchanged. If you skip the gen key, GET the blob every tick and compare to the last raw string.

Prefix with IdentityHex as today.

### Semantics to preserve (tests already exist)

pkg/decisionscope ban-wins, upsert, remove, batch, none-mode skips Range index.
Redis replicas that never ingest the stream still match Range (they hydrate from the blob on the ticker).
Header scopes and exact IP keys unchanged.

### Files an implementer should open first

pkg/crowdsecconnection/connection.go (handleStreamCache, startStream)
pkg/decisionscope/lookup.go, range.go
pkg/iplookup/iplookup.go
knowledge/devdocs/core_plugin_decisionscope.md, core_plugin_ip.md
openspec/specs/core_plugin_decisionscope/spec.md (will need a delta: request path no longer walks the blob)
openspec/specs/core_plugin_ip_radix-lookup/spec.md (today requires Range stay a per-network walk — that requirement must change)

### Out of scope unless asked

Making "updated" a real lock (SET NX).
Per-request gen-key check.
Storing CIDRs as many Redis keys.
Teaching iplookup a remediation payload.

### Assumed decisions (human can override)

Hydrate/rebuild on ticker, not ServeHTTP.
Two boolean trees, not LPM-with-value.
Rebuild from blob, no delete API this change.
Optional generation key; blob compare is enough if Range lists stay small.

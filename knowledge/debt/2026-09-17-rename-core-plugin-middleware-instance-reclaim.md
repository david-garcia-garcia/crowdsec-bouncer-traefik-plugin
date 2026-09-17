# Rename `core_plugin_middleware_instance-reclaim` → a leaf that names settings-hash vs session

IssueKey: 2026-09-17-lapi-transport-router-policy
Size: large
Action: note

## Why this follow-up
Leaf `instance-reclaim` hides whether the unit is session prefix, settings hash, transport adopt, or Bouncer policy. This change folded hash drop, last-wins TLS, and Bouncer Redis-fail-closed/live-TTL into that folder.

## Why it was not taken
Many dependents and archive folders. Unattended take is only small rows on files this run created. Do not rename a vague family without approval.

## Risks
Later packets keep folding reclaim-key, transport, and per-router policy into the same vague leaf.

## Context
Current: `openspec/specs/core_plugin_middleware_instance-reclaim`
Proposed: a legal 4th part that names the remaining unit after a human picks the split (settings-hash vs session-key vs instance-reclaim).

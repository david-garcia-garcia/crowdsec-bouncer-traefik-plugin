## Why

Stream and alone Range matching walks the shared `range-index` blob on every request. Allowed traffic (the common miss) pays O(n) CIDR tests. Trusted-IP already has prefix-bounded membership; Range was left linear and is now the hot path.

## What Changes

- Keep `range-index` (`cidr=remediation` lines) as the durable shared document (Redis or process map).
- Add in-process Range membership on the reclaimed Crowdsec connection: two boolean CIDR sets (ban, captcha). Stream/alone request lookup uses that membership, not a blob walk. Ban still wins if several containing CIDRs hit.
- Every pod’s stream ticker hydrates membership from the blob (lease miss: after apply; lease hit: GET blob and rebuild if the raw string changed). Hydrate once at stream start from the existing blob (no extra LAPI poll).
- live/none still skip `range-index` and expand Range via LAPI `?ip=`.
- Trusted-IP Checker stays separate. No Range payload on the CIDR helper. No `range-index-gen` key. **Not BREAKING.**

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_plugin_decisions_scopes`: Stream/alone Range request matching uses in-process membership rebuilt from `range-index`. Redis replicas that skip LAPI still match after hydrating from the blob. Ban still wins. Client IP still comes from `GetRemoteIP`.
- `core_plugin_ip_radix-lookup`: Drop the requirement that Range stay a per-network walk. Range may reuse boolean CIDR prefix membership; it MUST NOT store remediations on that helper or share the trusted-IP Checker.

## Impact

- `pkg/crowdsecconnection` (startStream, handleStreamCache, connection-held membership).
- `pkg/decisionscope` (lookup keys, membership from blob, ban-then-captcha).
- `pkg/bouncer` ServeHTTP lookup call.
- `pkg/iplookup` reused as-is (no delete API, no payload).
- Usage packets `knowledge/devdocs/core_plugin_decisionscope.md`, `knowledge/devdocs/core_plugin_ip.md`.

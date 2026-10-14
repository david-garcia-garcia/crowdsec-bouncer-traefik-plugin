# Explore

## Concepts

- **README operator docs** — `README.md`. Job: tell operators how `appsecBodyLimit` interacts with bot-detection submit. Two seams: the AppSec / bot-detection paragraph (line 155) and the **AppsecBodyLimit** key (lines 619–620). The WARNING at line 530 is a third surface; it is not named in Desired.
- **AppSec body copy** — `pkg/appsec/query.go` `newAppsecBodyRequest`. Job: copy a readable POST/PUT/PATCH/DELETE body to AppSec. `appsecBodyLimit > 0` wraps `io.LimitReader`; `0` skips the cap and `io.ReadAll`s the whole readable body. No log names `/crowdsec-internal/challenge/submit`.
- **Existing proof** — `pkg/appsec/zzz_query_test.go` `Test_appsecQuery_zeroBodyLimitForwardsPost`. Job: prove limit `0` POSTs the full payload and restores it for origin.
- **Live contract (unchanged)** — `openspec/specs/core_plugin_appsec_client/spec.md` already requires `0` = unlimited. Usage `knowledge/devdocs/core_plugin_appsec.md` already says the same.

```
browser POST /crowdsec-internal/challenge/submit
        │
        ▼
  query.go body copy ── limit>0? LimitReader : full ReadAll
        │
        ▼
  AppSec listener (engine; not in this tree)
```

Call sites this change would touch: 2 named README sections. Roots searched: `README.md`, `pkg/appsec/query.go`, `pkg/appsec/zzz_query_test.go`, `openspec/specs/core_plugin_appsec_client/spec.md`, `knowledge/devdocs/core_plugin_appsec.md`, `knowledge/research/ext_crowdsec_appsec_bot-detection/notes.md`.

Reproduce:
- `go test ./pkg/appsec -run Test_appsecQuery_zeroBodyLimitForwardsPost -count=1` → pass (`ok` 1.085s). Limit `0` forwards the full POST body. Do not change that path.
- README gap: reproduced by reading `README.md` lines 155 and 619–620. Neither says `/crowdsec-internal/challenge/submit` must reach AppSec with the full form.
- Engine “truncated proof → forever challenge”: not reproduced (no CrowdSec AppSec engine in this run).

Outside facts: `knowledge/research/ext_crowdsec_appsec_bot-detection/` (submit is POST of PoW + fingerprint; POST body must be relayed). Upstream https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/403 point 6 documents the same operator warning but says limit `0` sends no body — false on this fork.

## Decisions

- Seam: README only. Add the submit-body warning to the AppSec / bot-detection paragraph and the **AppsecBodyLimit** key. State: full form required; default 10MB is enough; a smaller positive limit cuts the proof short; `0` means no limit (the whole body is sent).
- Rejected: changing `query.go`, adding a truncation log, adding a duplicate test, copying upstream’s “`0` sends no body”, expanding the line-530 WARNING, opening the PR against `main` (upstream mirror).
- Live contract: no live contract change. `core_plugin_appsec_client` already owns `0` = unlimited. Operator README is not a spec leaf.

## Open questions

- Q: Does CrowdSec AppSec reject a truncated `/crowdsec-internal/challenge/submit` body and re-challenge forever?
  Rank: additive asked — Desired names the forever-challenge consequence as the reason to document; no engine code moves
  Decision: assumed — write the operator warning as asked; do not claim this run measured the engine. Research already says the POST body must be relayed; upstream PR 403 asserts reject-and-retry.
  By: explore

- Q: Is a typical challenge-submit form always under the 10MB default?
  Rank: additive asked — Desired says the default 10MB is enough
  Decision: assumed — write that the default is enough; do not invent a measured form size.
  By: explore

- Q: Should the line-530 WARNING also name the challenge proof?
  Rank: additive incidental — Desired names the AppSec / bot-detection section and the AppsecBodyLimit key, not that WARNING
  Decision: assumed — leave the WARNING as-is. Bound the ask.
  By: explore

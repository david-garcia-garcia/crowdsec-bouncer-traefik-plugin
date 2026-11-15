## Context

See proposal.md — Why. Runtime already implements `appsecBodyLimit` `0` as unlimited (`pkg/appsec/query.go` skips `io.LimitReader`). `Test_appsecQuery_zeroBodyLimitForwardsPost` already proves the POST. Operator README at the AppSec / bot-detection paragraph and the **AppsecBodyLimit** key does not mention `/crowdsec-internal/challenge/submit`.

## Goals / Non-Goals

**Goals:**
- Two README seams say the same facts: submit needs the full form; default 10MB is enough; a smaller positive limit cuts the proof short; `0` means no limit (whole body sent).
- Keep the existing test as the only proof. Re-run it.

**Non-Goals:**
- Do not change `query.go`, metrics, or challenge-path 404.
- Do not add a log that names the challenge submit.
- Do not expand the line-530 WARNING.
- Do not write that `0` sends nothing (upstream PR 403 wording).

## Decisions

- **Edit README only.** The product gap is operator wording, not the copy path. Alternative: fold a README SHALL into `core_plugin_appsec_client` — rejected; that leaf already owns `0` = unlimited, and operator docs are not a runtime contract.
- **Say `0` is unlimited.** Alternative: copy upstream “`0` sends no body” — rejected; false on this fork (`query.go` + existing test).
- **Name `/crowdsec-internal/challenge/submit` on both named seams.** Alternative: one seam only — rejected; Desired names both.

## Risks / Trade-offs

- [Risk] An operator coming from upstream PR 403 expects `0` to send no body. → Mitigation: both seams say `0` means no limit and the whole body is sent.
- [Risk] The engine reject-and-retry path was not measured here. → Mitigation: document the operational warning as asked; do not claim a measured engine run.

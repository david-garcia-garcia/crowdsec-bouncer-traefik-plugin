# Spec

1. [judgement] Extra CRS-ban Pester case — `tests/e2e/real/appsec.Tests.ps1:127` — `tasks.md` 3.4 names one case (under the limit passes, next is 429 with ban page and `ban:appsec`). The diff adds a second It, "Should keep bouncerRemediationStatusCode for a CRS ban on the same listener". It supports the MODIFIED requirement's "any other http_status uses bouncerRemediationStatusCode" scenario, but no task or scenario asks for it.
   Fix: Keep it and add a line to tasks.md 3.4, or remove the second It
   Status: done
   Argument: Kept the case; tasks.md 3.4 now names the CRS-ban-stays-403 check, which proves the "other http_status" scenario on a real listener.
2. [judgement] Proposal Impact names a file the apply did not touch — `openspec/changes/appsec-ban-keeps-429/proposal.md:Impact` — Impact lists `tests/e2e/real/config/acquis.d/appsec-bot.yaml`. `design.md` and the diff change `tests/e2e/real/config/acquis.yaml` instead. The diff matches design and tasks 3.2, so the diff is right and the proposal text is stale.
   Fix: Replace `acquis.d/appsec-bot.yaml` with `acquis.yaml` in the proposal Impact list
   Status: done
   Argument: Proposal Impact now lists `tests/e2e/real/config/acquis.yaml`.

# Test coverage

1. [hard] Critical path untested — `pkg/lapi/decisionstore.go:40` — `OpenDecisionStore` passes `countActiveFromMode(cfg.CrowdsecMode)` into `Open`; tests that prove the gauge call `NewMemory`/`NewRedis`/`AttachTestInternStore` with a hardcoded bool. Existing `OpenDecisionStore`+`putBan` tests (`pkg/lapi/zzz_decisionstore_test.go`) assert lookup/prefix only. Reverting `countActiveFromMode` to always false leaves `TestActiveCountsStreamPutDelete` and `TestReportMetricsOfficialLabels` green.
   → Assert `OpenDecisionStore` with stream Put increments `ActiveCounts`, and live Put leaves the snapshot empty
   Status: done
   Argument: TestOpenDecisionStore_CountActiveFromMode asserts stream Put increments and live Put does not.
2. [judgement] Happy path only — `pkg/decisionstore/redis.go:252` — Redis `adjustPutCounts`/`adjustDeleteCounts` no-op when `countActive` is false; `TestActiveCountsLivePutDoesNotIncrement` hits that outcome only on memory. Redis tests cover the counted Put/Delete/overwrite arms.
   → Assert `NewRedis(..., false)` Put leaves `ActiveCounts` empty, or skip if live Redis is unreachable for this gauge
   Status: skipped
   Argument: judgement; counted Redis Put/Delete/overwrite already covered; live no-increment is proven on memory.

# Gate `lapi.Prepare` Redis password resolve

IssueKey: 2026-09-18-redis-password-file-checked-when-disabled
Size: small
Action: note

## Why this follow-up
`lapi.Prepare` still calls `GetVariable` for `RedisCachePassword` with no `RedisCacheEnabled` guard. The error is discarded, so a missing file empties the string field; a leftover valid file still loads and hashes into the DecisionStore reclaim key while Redis is off.

## Why it was not taken
This ticket bounds the ask to the `ValidateParams` startup gate. Unattended take is only small rows on files this run created.

## Risks
After the ValidateParams gate, `plugin.New` can still Stat a stale password file at Prepare. Disabled Redis plus a leftover readable file still injects that password into `storeParams`.

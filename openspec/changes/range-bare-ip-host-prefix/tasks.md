## 1. Host-prefix owner

- [x] 1.1 Export `pkg/ip.HostCIDR` with the current `hostCIDR` body; `NewChecker` calls the exported name
- [x] 1.2 Do not change trusted-pool outcomes

## 2. Range index and membership

- [x] 2.1 Canonicalize a parseable bare IP to `HostCIDR` at `ApplyRangeBatch` upsert and remove
- [x] 2.2 Canonicalize again in `MembershipFromIndex` before `AddCIDR` and when storing the cidr→remediation key
- [x] 2.3 Leave stream `rememberActiveDecision("range:"+value)` keys as trimmed `decision.Value`

## 3. Spec and tests

- [x] 3.1 Apply the `core_plugin_decisions_scopes` host-prefix sentence and scenario
- [x] 3.2 Regression: Range host `192.0.2.1` remediates that address; a neighbor does not; unparseable lines stay skipped
- [x] 3.3 Delete of the original bare spelling drops the remediating line

## 4. Verify

- [x] 4.1 `go test ./pkg/ip/ ./pkg/decisionscope/`

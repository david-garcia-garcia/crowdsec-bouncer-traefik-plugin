## 1. Host-prefix owner

- [ ] 1.1 Export `pkg/ip.HostCIDR` with the current `hostCIDR` body; `NewChecker` calls the exported name
- [ ] 1.2 Do not change trusted-pool outcomes

## 2. Range index and membership

- [ ] 2.1 Canonicalize a parseable bare IP to `HostCIDR` at `ApplyRangeBatch` upsert and remove
- [ ] 2.2 Canonicalize again in `MembershipFromIndex` before `AddCIDR` and when storing the cidr→remediation key
- [ ] 2.3 Leave stream `rememberActiveDecision("range:"+value)` keys as trimmed `decision.Value`

## 3. Spec and tests

- [ ] 3.1 Apply the `core_plugin_decisions_scopes` host-prefix sentence and scenario
- [ ] 3.2 Regression: Range host `192.0.2.1` remediates that address; a neighbor does not; unparseable lines stay skipped
- [ ] 3.3 Delete of the original bare spelling drops the remediating line

## 4. Verify

- [ ] 4.1 `go test ./pkg/ip/ ./pkg/decisionscope/`

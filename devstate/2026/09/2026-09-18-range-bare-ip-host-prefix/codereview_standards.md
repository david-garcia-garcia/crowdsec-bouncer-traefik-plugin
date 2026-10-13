# Standards

1. [hard] Name for the scope — `pkg/decisionscope/range.go:12` — `value` is the LAPI/spec nickname, not the role this body uses (`network`) or the sibling range-index parameter (`cidr`)
   → Rename the parameter to `cidr`
   Status: done
   Argument: renamed parameter to `cidr`.
   ```
   func rangeIndexCIDR(value string) string {
   	network := strings.TrimSpace(value)
   ```

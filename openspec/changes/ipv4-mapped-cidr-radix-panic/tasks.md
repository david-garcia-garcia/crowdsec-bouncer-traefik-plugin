## 1. Insert remap

- [ ] 1.1 In `insert`, when `To4()` is non-nil and mask `bits==128`, remap prefix to `ones-96` and walk the v4 root from bit 96 for that length; store the remapped length on the node
- [ ] 1.2 Leave native IPv4 (`bits==32`) and native IPv6 (`To4()` nil) walks unchanged; do not reject a mapped CIDR at `AddCIDR`

## 2. Hunt regressions

- [ ] 2.1 `TestHunt_IPv4MappedSlash96DoesNotPanic` in `pkg/iplookup/zzz_iplookup_test.go`: no panic; Contains-equivalent membership for IPv4, IPv4-mapped, native IPv6 miss, and `/120` as `/24`
- [ ] 2.2 `TestHunt_NewCheckerIPv4MappedSlash96` in `pkg/ip/zzz_checker_test.go`: construction succeeds; `192.0.2.1` is trusted
- [ ] 2.3 `TestHunt_MembershipIPv4MappedCIDRDoesNotPanic` in `pkg/decisionscope/zzz_rangemembership_test.go`: `::ffff:0:0/96=t` does not panic and remediates IPv4 as ban

## 3. Specs and docs

- [ ] 3.1 Prefix the IPv4-mapped insert / Contains requirement into `openspec/specs/core_plugin_ip_radix-lookup/spec.md`
- [ ] 3.2 Add the IPv4-mapped remap gotcha to `knowledge/devdocs/core_plugin_ip.md`

## 4. Verify

- [ ] 4.1 `go build ./...`, `go vet ./...`, `go test ./pkg/iplookup ./pkg/ip ./pkg/decisionscope`, `go test .`, `golangci-lint run ./...`

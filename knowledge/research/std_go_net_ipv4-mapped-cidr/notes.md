# IPv4-mapped CIDR Contains

How Go `net.ParseCIDR` and `net.IPNet.Contains` treat IPv4-mapped IPv6 CIDRs such as `::ffff:0:0/96`. Pin: Go 1.25.6 (`go version go1.25.6 windows/amd64`).

## ParseCIDR keeps a 128-bit mask

`ParseCIDR("::ffff:0:0/96")` succeeds. The returned `IPNet.IP` is 16 bytes and `To4()` is non-nil. `Mask.Size()` is `ones=96, bits=128`. Owner: `golang/go@go1.25.6:src/net/ip.go` (`ParseCIDR`). Extract: `.sources/ip.go.md`.

`IPNet.String()` still prints the IPv4 form. Local probe on Go 1.25.6: `::ffff:0:0/96` → `0.0.0.0/0`; `::ffff:192.0.2.0/120` → `192.0.2.0/24`; `::ffff:192.0.2.1/128` → `192.0.2.1/32`. (authority: inference — `.sources/local-go1256-contains-probe.md`)

A mapped prefix shorter than `/96` masks away the `0xff 0xff` bytes, so `To4()` becomes nil. Probe: `::ffff:192.0.2.0/24` → `::/24`.

## Contains uses the last four mask bytes

`Contains` calls `networkNumberAndMask`. When `n.IP.To4()` is non-nil and the mask is 16 bytes, the mask is sliced to `m[12:]` (the last 32 bits). The query is also reduced with `To4()`. Native IPv6 (`To4() == nil`) has length 16 vs 4 and is a miss. Owner: `…@go1.25.6:src/net/ip.go` (`networkNumberAndMask`, `Contains`). Extract: `.sources/ip.go.md`.

So a mapped `/96` is an IPv4 `/0`; `/120` is an IPv4 `/24`; `/128` is an IPv4 `/32`. Probe: `::ffff:0:0/96` contains `192.0.2.1` and `::ffff:192.0.2.1`, not `2001:db8::1`.

## To4 is the IPv4-mapped prefix

`To4()` is non-nil for a 4-byte IP, or for a 16-byte IP whose first 10 bytes are zero and bytes 10–11 are `0xff`. Owner: `…@go1.25.6:src/net/ip.go` (`To4`). Extract: `.sources/ip.go.md`.

## Sources

- Official: [net.IPNet.Contains](https://pkg.go.dev/net#IPNet.Contains), [net.ParseCIDR](https://pkg.go.dev/net#ParseCIDR)
- Source: `golang/go@go1.25.6:src/net/ip.go`
- Extracts: `.sources/`

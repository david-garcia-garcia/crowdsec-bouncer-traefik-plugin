[Documentation](../README.md) › [How-to](README.md) › Let a LAN or VPN through

# Let a LAN or VPN through

`bouncerClientTrustedIps` lets these client addresses skip all checks, AppSec included. See [examples/trusted-ips](../../examples/trusted-ips/README.md).

```yaml
bouncerClientTrustedIps:
  - 192.168.1.0/24
```

The address checked is the [real client IP](behind-proxy.md), not the proxy's, when a trusted proxy is configured.

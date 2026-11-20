[Documentation](../README.md) › [How-to](README.md) › Remediate the visitor, not the proxy

# Remediate the visitor, not the proxy

Behind Cloudflare, a load balancer, or another reverse proxy, every connection comes from the proxy. Unless you tell the plugin to trust the proxy, every visitor is treated as the proxy's IP.

List the proxy's addresses in [`bouncerForwardedHeadersTrustedIps`](../configuration.md#bouncerforwardedheaderstrustedips) and set [`bouncerForwardedHeadersCustomName`](../configuration.md#bouncerforwardedheaderscustomname) to the header that proxy sends with the real client IP (`CF-Connecting-IP`, `X-Forwarded-For`, or `X-Real-Ip`). See [examples/behind-proxy](../../examples/behind-proxy/README.md), and the setting descriptions for details.

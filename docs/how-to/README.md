[Documentation](../README.md) › How-to

# How-to guides

Common tasks and the settings behind them. The [Configuration reference](../configuration.md) lists every setting.

| I want to… | Guide |
| ---------- | ----- |
| Check that bans and captchas work, from a browser or with a real decision | [Test a ban or a captcha](test-ban-or-captcha.md) |
| Know why a request was blocked | [See the verdict in access logs](verdict-in-access-logs.md) |
| Let visitors quote a request id to support | [Put a request id on the ban page](request-id-on-ban-page.md) |
| Challenge community-blocklist IPs instead of banning them | [Show a community ban as a captcha](community-ban-as-captcha.md) |
| Keep a strict CSP and still serve the challenge and the captcha | [Keep a Content-Security-Policy](content-security-policy.md) |
| Stop API clients from receiving a captcha page | [Keep captchas off API routes](captcha-off-api-routes.md) |
| Cap how often a client, a token or a tenant calls a route | [Limit how often a client calls a route](../rate-limit.md) |
| Let my office, LAN or VPN skip the checks | [Let a LAN or VPN through](trusted-ips.md) |
| Run behind Cloudflare, a load balancer or another proxy | [Remediate the visitor, not the proxy](behind-proxy.md) |
| Decide between failing open and failing closed | [Choose what happens when CrowdSec is down](crowdsec-down.md) |
| Add OWASP CRS next to AppSec, tune it, and read why it blocked | [ModSecurity (OWASP CRS)](../modsecurity.md) |
| Keep gRPC streams and long uploads working behind AppSec or ModSec | [Run streaming request bodies through the WAF legs](streaming-request-bodies.md) |
| Act on country or ASN decisions | [Match a country or an ASN](country-or-asn.md) |

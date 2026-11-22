[README](../README.md) › Documentation

# Documentation

Start with the [README](../README.md) for what the plugin does and a minimal setup. Then pick the page for what you want to do.

## Understand

| Page | What it covers |
| ---- | -------------- |
| [How the middleware works](how-it-works.md) | The legs (LAPI, rate limit, AppSec, captcha, ModSec), the order of the checks, what the middleware that connects holds and what stays per router |
| [When a dependency is down](failure-modes.md) | What each leg does when LAPI, AppSec, the ModSecurity sidecar, Redis or the captcha provider fails, and the settings that decide it |
| [Concepts](concepts.md) | CrowdSec terms, decisions and scopes, ban and captcha, AppSec and bot detection, LAPI modes, metrics, cache |
| [Middleware architecture](middleware-architecture.md) | One middleware or several: sharing a connection between routers, holding connections on a router with no backend, several engines, AppSec only |
| [LAPI modes in detail](modes.md) | Sequence diagrams for `stream`, `live`, `none` and `alone` |

## Set up

| Page | What it covers |
| ---- | -------------- |
| [Configuration reference](configuration.md) | Static and dynamic Traefik configuration, and every setting grouped by area |
| [Connect to CrowdSec](connect-to-crowdsec.md) | LAPI key, client certificates, HTTPS to LAPI and AppSec |
| [ModSecurity (OWASP CRS)](modsecurity.md) | The CRS sidecar: how the leg works, speed, setup, tuning, reading why a request was blocked |
| [Rate limit](rate-limit.md) | Buckets, keys, algorithms, captcha before a hard limit, one policy for several routers, Redis outages |
| [How-to guides](how-to/README.md) | Ten common tasks: test a ban, read the verdict in logs, run behind a proxy, keep captchas off APIs… |

## Examples

Each example is a runnable Docker Compose setup, except Kubernetes and the binary VM.

| Example | Shows |
| ------- | ----- |
| [behind-proxy](../examples/behind-proxy/README.md) | Behind another proxy service (ex: Cloudflare) |
| [redis-cache](../examples/redis-cache/README.md) | Redis as an external shared cache |
| [trusted-ips](../examples/trusted-ips/README.md) | Trusted IPs (ex: LAN or VPN) that CrowdSec does not filter |
| [binary-vm](../examples/binary-vm/README.md) | CrowdSec and Traefik installed as binaries in a single VM |
| [tls-auth](../examples/tls-auth/README.md) | HTTPS and TLS authentication with CrowdSec |
| [kubernetes](../examples/kubernetes/README.md) | CrowdSec and Traefik in Kubernetes |
| [standalone-mode](../examples/standalone-mode/README.md) | Traefik in standalone mode, without CrowdSec |
| [appsec-enabled](../examples/appsec-enabled/README.md) | AppSec enabled |
| [captcha](../examples/captcha/README.md) | Captcha remediation |
| [custom-ban-page](../examples/custom-ban-page/README.md) | A custom ban HTML page |
| [custom-captcha](../examples/custom-captcha/README.md) | A custom Wicketkeeper captcha |
| [geoenrich-decisions](../examples/geoenrich-decisions/README.md) | A geoenrich plugin for CrowdSec country decisions |
| [modsecurity](../examples/modsecurity/README.md) | An OWASP CRS (ModSecurity) sidecar next to LAPI and AppSec |

## Contribute

| Page | What it covers |
| ---- | -------------- |
| [Development](development.md) | Tests, local plugin mode, design notes |

[Documentation](README.md) › Middleware architecture

# Middleware architecture

Most installs need a single middleware with everything enabled (see [One middleware](#one-middleware-all-in-one)). Read the rest of this page if you protect several routers with different settings, or use several CrowdSec engines. The concepts behind it (legs, what lives on the middleware that connects and what stays per router, reloads) are in [How the middleware works](how-it-works.md).

A middleware can do two jobs:

1. **Connect** to CrowdSec. Each connection is turned on separately and is shared under a name. The default is the name Traefik gives the middleware, which includes the provider: `stream@file` for a middleware `stream` in the file provider, `<namespace>-<name>@kubernetescrd` for a Kubernetes CRD. A router that subscribes with the bare `stream` does not find that connection; set the instance name explicitly on the middleware that connects, or write the full name:

   | Connection | Turn on with | Shared as |
   | ---------- | ------------ | --------- |
   | LAPI (decisions) | `lapiEnabled: true` | `lapiInstanceName` |
   | AppSec (WAF) | `appsecEnabled: true` | `appsecInstanceName` |
   | Captcha provider | `captchaEnabled: true` | `captchaInstanceName` |
   | ModSecurity CRS sidecar | `modsecEnabled: true` | `modsecInstanceName` |
   | Rate limit (Redis counters and the bucket policy) | `rateLimitEnabled: true` | `rateLimitInstanceName` |

2. **Protect** the router it is attached to (`bouncerEnabled: true`), using the connections it names.

A middleware that only protects sets `bouncerEnabled: true` plus the instance names it wants to use, and leaves the `*Enabled` connection flags off. It does not repeat the host, key, or interval: those live on the middleware that connects. It keeps its own request settings (status code, captcha, trusted IPs, behavior when CrowdSec or a WAF is down, response headers). The rate limit is the exception: its buckets and the rest of its policy live on the middleware that connects (see [Limit how often a client calls a route](rate-limit.md)). LAPI, AppSec, captcha, ModSec, and rate-limit names are independent, so all five can be called `shared`.

```mermaid
flowchart LR
  subgraph traefik ["One Traefik process"]
    B1["Bouncer /api"]
    B2["Bouncer /admin"]
    B3["Bouncer /tenant-b"]
    L1["LAPI client shared"]
    L2["LAPI client tenant-b"]
    A1["AppSec client shared"]
  end
  CS1["CrowdSec engine A"]
  CS2["CrowdSec engine B"]
  B1 --> L1
  B2 --> L1
  B1 --> A1
  B2 --> A1
  B3 --> L2
  L1 --> CS1
  A1 --> CS1
  L2 --> CS2
```

Right after Traefik starts or reloads, a connection can take a moment to become available. Until it does, a request that needs that connection uses the configured failure action. [Connections on a router with no backend](#connections-on-a-router-with-no-backend) shows how to keep that window short.

The settings involved are listed in [Configuration › Connections and sharing](configuration.md#connections-and-sharing).

## One middleware (all-in-one)

No instance names needed: the middleware connects and protects on its own.

```yaml
api-crowdsec:
  plugin:
    bouncer:
      appsecEnabled: true
      appsecKey: "..."
      bouncerEnabled: true
      lapiEnabled: true
      lapiHost: crowdsec:8080
      lapiKey: "..."
      lapiMode: stream
```

## Shared connection, per-router settings

`cs` connects to LAPI and AppSec and shares both as `shared`. `cs-admin` reuses them and only adds its own setting.

```yaml
cs:
  plugin:
    bouncer:
      appsecEnabled: true
      appsecInstanceName: shared
      appsecKey: "..."
      bouncerEnabled: true
      lapiEnabled: true
      lapiHost: crowdsec:8080
      lapiInstanceName: shared
      lapiKey: "..."
      lapiMode: stream
cs-admin:
  plugin:
    bouncer:
      appsecInstanceName: shared
      bouncerEnabled: true
      bouncerRemediationHeadersCustomName: x-crowdsec
      lapiInstanceName: shared
```

## Connections on a router with no backend

If you prefer the connections to live in a middleware that protects nothing, set `bouncerEnabled: false` on it. Traefik only loads a middleware that is attached to a router, so give it a router of its own that needs no backend: the built-in `noop@internal` service (it answers every request with HTTP 418) and a rule no visitor sends.

```yaml
http:
  routers:
    crowdsec-holders:
      rule: Host(`crowdsec-holders.invalid`)
      service: noop@internal
      middlewares:
        - cs-holders
  middlewares:
    cs-holders:
      plugin:
        bouncer:
          appsecEnabled: true
          appsecInstanceName: shared
          appsecKey: "..."
          bouncerEnabled: false
          lapiEnabled: true
          lapiHost: crowdsec:8080
          lapiInstanceName: shared
          lapiKey: "..."
          lapiMode: stream
```

The routers you protect then use `bouncerEnabled: true` with `lapiInstanceName: shared` and `appsecInstanceName: shared`, as `cs-admin` does above.

Why a router of its own, and not one of your application routers:

- **A router whose service cannot be built never loads its middlewares.** A missing service or invalid TLS options leave the connection unpublished until the next configuration change. `noop@internal` always builds.
- **On Docker, a router only exists while its container runs and, if the container has a healthcheck, while it is healthy** (unless `providers.docker.allowEmptyServices=true`). Holding the connections on an application container ties every router that uses them to that one container.
- **Traefik loads each provider's routers as soon as that provider reports them; it does not wait for the others.** Instance names work across providers, but a router from another provider can take requests before the holder is loaded, and those requests get the failure action. Keep the holder in the same provider as the routers that use it.

Inside one configuration, the order does not matter: Traefik builds every router before any of them takes a request.

## Several LAPI streams or CrowdSec engines

CrowdSec tracks one stream per combination of **bouncer API key and the IP Traefik connects from**. Two LAPI connections with the same key from the same Traefik interfere with each other. Each separate stream needs its own bouncer key (and its own host if it is another engine).

Give each connection its own name, and point each protecting middleware at the one it should use:

```yaml
cs-a:
  plugin:
    bouncer:
      bouncerEnabled: true
      lapiEnabled: true
      lapiHost: crowdsec-a:8080
      lapiInstanceName: engine-a
      lapiKey: "key-a"
      lapiMode: stream
cs-b:
  plugin:
    bouncer:
      bouncerEnabled: true
      lapiEnabled: true
      lapiHost: crowdsec-b:8080
      lapiInstanceName: engine-b
      lapiKey: "key-b"
      lapiMode: stream
app-a:
  plugin:
    bouncer:
      bouncerEnabled: true
      lapiInstanceName: engine-a
app-b:
  plugin:
    bouncer:
      bouncerEnabled: true
      lapiInstanceName: engine-b
```

`app-a` and `app-b` run in the same Traefik but see different decisions. The same pattern works for two streams from one engine, using two bouncer keys.

## AppSec only

No decision lookup; only the WAF.

```yaml
waf:
  plugin:
    bouncer:
      appsecEnabled: true
      appsecHost: crowdsec:7422
      appsecKey: "..."
      bouncerEnabled: true
      lapiEnabled: false
```

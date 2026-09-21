# CrowdSec modes

How this plugin fetches decisions and what happens on a request. The README lists a one-line summary of each `LapiMode`; this page is the sequence for each path.

## none

Every request asks LAPI. No decision cache.

> A ban decision exists in CrowdsecLAPI

```mermaid
sequenceDiagram
    participant User
    participant TraefikPlugin
    User->>TraefikPlugin: Can I access that webpage
    create participant CrowdsecLAPI
    TraefikPlugin-->>CrowdsecLAPI: Does the User IP has a Crowdsec Decision ?
    destroy CrowdsecLAPI
    CrowdsecLAPI-->>TraefikPlugin: Yes a ban Decision
    TraefikPlugin->>User: No, HTTP 403
```

> No decision in CrowdsecLAPI

```mermaid
sequenceDiagram
    participant User
    participant TraefikPlugin
    User->>TraefikPlugin: Can I access that webpage
    create participant CrowdsecLAPI
    TraefikPlugin-->>CrowdsecLAPI: Does the User IP has a crowdsec decision ?
    destroy CrowdsecLAPI
    CrowdsecLAPI-->>TraefikPlugin: Nothing, all good!
    destroy TraefikPlugin
    TraefikPlugin->>Webserver: Forwarding this HTTP Request from User
    Webserver->>User: HTTP Response
```

## live

Ask LAPI on a cache miss, then store that IP's result for `BouncerLiveTtlSeconds`.

> A ban decision exists in CrowdsecLAPI but not in cache

```mermaid
sequenceDiagram
    participant User
    participant TraefikPlugin
    User->>TraefikPlugin: Can I access that webpage
    create participant PluginCache
    TraefikPlugin-->>PluginCache: Does the User IP has a crowdsec decision ?
    PluginCache-->>TraefikPlugin: Nothing, all good!
    create participant CrowdsecLAPI
    TraefikPlugin-->>CrowdsecLAPI: Does the User IP has a crowdsec decision ?
    destroy CrowdsecLAPI
    CrowdsecLAPI-->>TraefikPlugin: Yes a ban Decision
    TraefikPlugin-->>PluginCache: Store the information for this IP for BouncerLiveTtlSeconds
    destroy PluginCache
    PluginCache-->>TraefikPlugin: Done
    TraefikPlugin->>User: No, HTTP 403
```

> No decision in cache

```mermaid
sequenceDiagram
    participant User
    participant TraefikPlugin
    User->>TraefikPlugin: Can I access that webpage
    create participant PluginCache
    TraefikPlugin-->>PluginCache: Does the User IP has a crowdsec decision ?
    PluginCache-->>TraefikPlugin: Nothing, all good!
    create participant CrowdsecLAPI
    TraefikPlugin-->>CrowdsecLAPI: Does the User IP has a crowdsec decision ?
    destroy CrowdsecLAPI
    CrowdsecLAPI-->>TraefikPlugin: Nothing, all good!
    TraefikPlugin-->>PluginCache: Store the information for this IP for BouncerLiveTtlSeconds
    destroy PluginCache
    PluginCache-->>TraefikPlugin: Done
    TraefikPlugin->>Webserver: Forwarding this HTTP Request from User
    Webserver->>User: HTTP Response
```

## stream

Sync the decision list from LAPI every `LapiUpdateIntervalSeconds`. The request path hits cache only.

> Cache synchronization every LapiUpdateIntervalSeconds

```mermaid
sequenceDiagram
    participant TraefikPlugin
    participant CrowdsecLAPI
    TraefikPlugin->>CrowdsecLAPI: What are the current decisions
    destroy CrowdsecLAPI
    CrowdsecLAPI->>TraefikPlugin: Here is the list
    create participant PluginCache
    TraefikPlugin-->>PluginCache: Store this list
    destroy PluginCache
    PluginCache-->>TraefikPlugin: Done
```

> A ban decision exists in cache

```mermaid
sequenceDiagram
    participant User
    participant TraefikPlugin
    User->>TraefikPlugin: Can I access that webpage
    create participant PluginCache
    TraefikPlugin-->>PluginCache: Does the User IP has a crowdsec decision ?
    destroy PluginCache
    PluginCache-->>TraefikPlugin: Yes a ban decision
    destroy TraefikPlugin
    TraefikPlugin->>User: No, HTTP 403
```

> No decision in cache

```mermaid
sequenceDiagram
    participant User
    participant TraefikPlugin
    User->>TraefikPlugin: Can I access that webpage
    create participant PluginCache
    TraefikPlugin-->>PluginCache: Does the User IP has a crowdsec decision ?
    destroy PluginCache
    PluginCache-->>TraefikPlugin: Nothing, all good!
    destroy TraefikPlugin
    TraefikPlugin->>Webserver: Forwarding this HTTP Request from User
    Webserver->>User: HTTP Response
```

## alone

Like stream, but the list comes from the CrowdSec Central API (CAPI), about every two hours. No local CrowdSec.

> Cache synchronization every 2 hours to the Crowdsec Central API

```mermaid
sequenceDiagram
    participant TraefikPlugin
    participant CrowdsecCAPI
    TraefikPlugin->>CrowdsecCAPI: What are the current decisions from CAPI
    destroy CrowdsecCAPI
    CrowdsecCAPI->>TraefikPlugin: Here is the list
    create participant PluginCache
    TraefikPlugin-->>PluginCache: Store this list
    destroy PluginCache
    PluginCache-->>TraefikPlugin: Done
```

> A ban decision exists in cache

```mermaid
sequenceDiagram
    participant User
    participant TraefikPlugin
    User->>TraefikPlugin: Can I access that webpage
    create participant PluginCache
    TraefikPlugin-->>PluginCache: Does the User IP has a crowdsec decision ?
    destroy PluginCache
    PluginCache-->>TraefikPlugin: Yes a ban decision
    destroy TraefikPlugin
    TraefikPlugin->>User: No, HTTP 403
```

> No decision in cache

```mermaid
sequenceDiagram
    participant User
    participant TraefikPlugin
    User->>TraefikPlugin: Can I access that webpage
    create participant PluginCache
    TraefikPlugin-->>PluginCache: Does the User IP has a crowdsec decision ?
    destroy PluginCache
    PluginCache-->>TraefikPlugin: Nothing, all good!
    destroy TraefikPlugin
    TraefikPlugin->>Webserver: Forwarding this HTTP Request from User
    Webserver->>User: HTTP Response
```

## AppSec-only (`lapiEnabled: false`)

Skip IP decisions. Send the HTTP request to CrowdSec AppSec (`appsecEnabled: true`).

> The request is detected as malicious

```mermaid
sequenceDiagram
    participant User
    participant TraefikPlugin
    User->>TraefikPlugin: Can I access that webpage
    create participant CrowdsecAppSec
    TraefikPlugin-->>CrowdsecAppSec: Is this request malicious ?
    destroy CrowdsecAppSec
    CrowdsecAppSec-->>TraefikPlugin: Yes I think so
    destroy TraefikPlugin
    TraefikPlugin->>User: No, HTTP 403
```

> The request is not detected as malicious

```mermaid
sequenceDiagram
    participant User
    participant TraefikPlugin
    User->>TraefikPlugin: Can I access that webpage
    create participant CrowdsecAppSec
    TraefikPlugin-->>CrowdsecAppSec: Is this request malicious ?
    destroy CrowdsecAppSec
    CrowdsecAppSec-->>TraefikPlugin: No I don't think so
    destroy TraefikPlugin
    TraefikPlugin->>Webserver: Forwarding this HTTP Request from User
    Webserver->>User: HTTP Response
```

## Captcha

A captcha decision shows a challenge. After the provider accepts it, the IP is clean for `bouncerCaptchaGracePeriodSeconds`.

```mermaid
sequenceDiagram
    participant User
    participant TraefikPlugin
    User->>TraefikPlugin: Can I access that webpage
    create participant PluginCache
    TraefikPlugin-->>PluginCache: Does the User IP has a Crowdsec Decision ?
    PluginCache-->>TraefikPlugin: Yes a Catpcha Decision
    TraefikPlugin->>User: Please complete this captcha
    User->>TraefikPlugin: Fine, done!
    create participant ProviderCaptcha
    TraefikPlugin-->>ProviderCaptcha: Is the validation OK ?
    destroy ProviderCaptcha
    ProviderCaptcha-->>TraefikPlugin: Yes
    TraefikPlugin-->>PluginCache: Set the User IP Clean for bouncerCaptchaGracePeriodSeconds
    destroy PluginCache
    PluginCache-->>TraefikPlugin: Done
    destroy TraefikPlugin
    TraefikPlugin->>Webserver: Forwarding this HTTP Request from User
    Webserver->>User: HTTP Response
```

# Requirement
IssueKey: 2026-09-22-bouncer-instance-severance

# Bouncer instance severance (original proposal)

This is the **named-client split** we settled on before the domain-prefix YAML rename. It does not rename existing keys. It does not replace `crowdsecLapiKey` with `lapiKey`, or `enabled` with `bouncerEnabled`. Knob renames are later.

Date of discussion: 2026-09-21. Plugin is still beta; breaking *behaviour* was acceptable. Breaking *every* config key was a later add-on and is out of this document.

---

## Problem

Every Traefik middleware `New` does three jobs at once:

1. Open a LAPI client (stream / live / none / alone).
2. Open an AppSec client (when `crowdsecAppsecEnabled` is true).
3. Bounce this router’s requests with those clients.

Sharing already exists, but only as an identity hash (LAPI URL+key, AppSec listener+key+bodyLimit). There is no operator-chosen name. Every bouncing router must copy the full LAPI/AppSec YAML. Create-time knobs are first-wins. `decisionScopeHeaders` unions from whoever happened to construct first.

The operator want: **per-route bounce policy** (remediation header, failure action, captcha, trusted IPs) and **shared LAPI / AppSec clients** named once.

A second, related pain: Traefik does not guarantee constructor order. A bouncing router can `New` before the middleware that opens the named clients.

---

## What we discussed and dropped

### A–E: hard split (`crowdsecMode: bouncer` + dummy routers)

The first sketch:

| | Idea |
|---|---|
| A | New `crowdsecMode: bouncer`. |
| B | That is the **only** mode that bounces. It never opens LAPI or AppSec; it **subscribes by name**. |
| C | Other modes only manage named LAPI/AppSec instances. |
| D | Non-bouncer modes **reject** traffic. They live on a **placeholder router** so Traefik still calls `New`. |
| E | A bouncer can be constructed **before** the named clients exist. |

Cheap per-route knobs (remediation header, remap, …) would live only on the bouncer.

**Dropped.** Dummy routers for simple setups felt wrong. One middleware must still be able to open LAPI, open AppSec, and bounce. `crowdsecMode: bouncer` as the only bounce path was rejected.

### `"nil"` instance sentinel

After dummy routers were dropped, AppSec-only was sketched as `crowdsecLapiInstanceName: "nil"` (quoted, because unquoted YAML `nil` is null and looks like “use this Traefik name”).

**Dropped.** AppSec-only is “this middleware does not manage LAPI,” not a magic instance name. That is `crowdsecLapiEnabled: false` (AppSec still uses `crowdsecAppsecEnabled`).

### Block `New` until the named client exists

**Dropped.** It deadlocks Traefik’s constructor when the bouncer is built first.

---

## Scope (what this change is)

Keep today’s public key names (`crowdsecMode`, `crowdsecLapiKey`, `crowdsecAppsecEnabled`, `enabled`, …). Add the smallest surface that severs **ownership of clients** from **bounce policy**.

In:

- Named LAPI and AppSec slots (`crowdsecLapiInstanceName` / `crowdsecAppsecInstanceName`).
- Enable flags for each leg. `crowdsecLapiEnabled` defaults **false**. `true` means this middleware owns a LAPI client: `New` calls `Open`, and the reclaim key inside `Open` wakes or creates that Client. `false` does not own. An omitted `crowdsecLapiInstanceName` is prepopulated to this Traefik middleware name only when `crowdsecLapiEnabled` is true. `crowdsecAppsecInstanceName` is prepopulated only when `crowdsecAppsecEnabled` is true. The bouncer subscribes when `enabled` is true and that leg's instance name is set after that prepopulation. A leg whose flag is false and whose instance name was left unset does not subscribe. `enabled` does not create a backend.
- Bounce switch stays `enabled` (default **false**, as today). It controls the bouncer only. `true` applies decisions. `false` still Opens if this middleware has secrets; it calls `next` and does not bounce. That is enough for a dummy router.
- Late bind: `New` never waits. A subscriber `New` that blocked until the owner `New` would deadlock when Traefik constructs the subscriber first. Each bouncing middleware holds **two optional** bound clients (`atomic.Value`): LAPI and AppSec, independently empty. Openers push into subscribers. `ServeHTTP` only Loads those fields. `streamStartupBlock` is a bouncer knob. On the request path, `true` asks whether every backend this bouncer subscribes to is published. One subscription checks only that backend. While any subscribed client is missing, `ServeHTTP` returns **503** and does not call `next`. That is not a wait inside `New`. When the flag is false, a missing subscribed client uses that leg's failure action.
- Reclaim: the **slot** is the instance name bouncers subscribe to, and LAPI and AppSec do not share a slot table. The same string can be published in both. The ownership `Open` key is the middleware name plus every knob of that client. LAPI: mode, scheme, host, path, key, TLS, effective HTTP timeout, Redis, `crowdsecLapiStreamScopes`, CAPI credentials, `updateIntervalSeconds`, `metricsUpdateIntervalSeconds`, `updateMaxFailure`, `crowdsecCapiScenarios`, and `defaultDecisionSeconds`. AppSec: scheme, host, path, key, body limit, TLS, effective HTTP timeout. The slot name is not part of it. `streamStartupBlock` is not part of it. The same middleware with the same settings Wakes that Client on reload. A different middleware name is a different Client. Bounce knobs, `enabled`, `crowdsecAppsecFailureAction`, and `decisionScopeHeaders` are not in the key.
- Lifecycle logs: backend **Create** and **Close** at INFO; **Sleep** and **Wake** at DEBUG. Bouncer bound/unbound at INFO. Stable strings so real e2e can assert **order**, not only HTTP.

Out:

- Renaming all keys to `lapi*` / `appsec*` / `bouncer*`.
- Old-key aliases (not needed if we do not rename).
- Decision remapping as a new product feature.
- Traefik core changes.
- Making dummy routers mandatory.
- The slot name as the Client reclaim key. The ownership key is the middleware name plus that client's settings. Two middlewares with the same settings are two Clients. They can still share one DecisionStore when `SessionHex` matches.

---

## Behaviour

Three independent jobs on the same middleware object:

```
  New(config, traefikName)
       │
       ├─ crowdsecLapiEnabled
       │     → own: Open, publish crowdsecLapiInstanceName
       ├─ enabled + crowdsecLapiInstanceName != nil
       │     → bouncer subscribes to crowdsecLapiInstanceName
       ├─ crowdsecAppsecEnabled
       │     → own: Open, publish crowdsecAppsecInstanceName
       ├─ enabled + crowdsecAppsecInstanceName != nil
       │     → bouncer subscribes to crowdsecAppsecInstanceName
       └─ enabled false → call next; an owner still Opens
```

`crowdsecLapiEnabled` means this middleware owns a LAPI client. `New` calls `Open`. The reclaim key inside `Open` is the middleware name plus the client settings, and that is what wakes the Client or creates it. `crowdsecAppsecEnabled` is the same for an AppSec client. An omitted instance name is prepopulated to this Traefik middleware name only when that leg's flag is true, and that happens before publish and before subscribe. An owner that also bounces then uses the same name on both sides. A leg whose flag is false keeps an unset name unset, so `enabled: true` does not subscribe to it. `enabled: false` does not subscribe. An owner with neither an API key nor a client certificate cannot build the client, so `Open` fails and `New` fails with it.

An omitted instance name is prepopulated to this Traefik middleware name only when `crowdsecLapiEnabled` or `crowdsecAppsecEnabled` is true for that leg. Publish uses that name. When `enabled` is true the bouncer subscribes to it too. A leg that is not owned, with the instance name left unset, is not subscribed.

### Open vs subscribe

| Flag | Instance | API key or client certificate | Result |
|---|---|---|---|
| `true` | omitted | present | Open under this Traefik name. `enabled: true` subscribes the bouncer to that same name. |
| `true` | `shared` | present | Open `shared`. `enabled: true` subscribes the bouncer to `shared` because the instance name is set. |
| `true` | any | absent | Owns, and `Open` cannot build the client. `New` fails. |
| `false` | `shared` | absent | `enabled: true` subscribes to `shared` and does not Open. `enabled: false` is a leftover instance name and `New` fails. |
| `false` | omitted | absent | The name stays unset. The bouncer does not subscribe. The leg is off. |

When `crowdsecAppsecEnabled` is true, `Prepare` fills an empty AppSec field from LAPI before the owner test. An empty `crowdsecAppsecKey` becomes `crowdsecLapiKey`. An empty `crowdsecAppsecScheme` becomes `crowdsecLapiScheme`. An explicit AppSec key or scheme is kept. The copy does not run when AppSec is disabled, so a LAPI key on an AppSec-off middleware is not a leftover AppSec secret. A bouncer holds no LAPI key and no AppSec key, so this copy has nothing to copy and the bouncer still only subscribes. A middleware that has the LAPI key and AppSec enabled owns the AppSec client as well, including when `crowdsecAppsecKey` was omitted. Changing `crowdsecLapiScheme` when the AppSec scheme was omitted changes the AppSec client. AppSec TLS material is not copied. An inherited `https` scheme still uses the AppSec CA and client certificate, which stay empty, so verification can fail while LAPI succeeds. That is assumed OK for this change and is recorded in `knowledge/debt/2026-09-22-appsec-tls-follows-lapi.md`. `crowdsecAppsecHost` is not copied. Its default stays `crowdsec:7422`. Changing `crowdsecLapiHost` does not move AppSec.

Config errors:

- `enabled: false`, leg flag false, and an instance name, API key, or client certificate is still set. Nothing owns and nothing subscribes.
- Leg flag true, with neither an API key nor a client certificate. `Open` cannot build the client, so `New` fails.
- LAPI is certificate-only (client certificate and key, no API key) and `crowdsecAppsecEnabled` is true with no AppSec API key and no AppSec client certificate. The key copy copies nothing, and TLS material is not copied, so AppSec `Open` cannot build a client. `New` fails as a unit. The route does not come up. That is a misconfiguration.

A bouncer that processes a request and finds a required LAPI or AppSec backend missing logs one WARN, `msg` `crowdsec bouncer backend missing`, with the middleware name, `leg`, and `instanceName`. It does not log the API key. This WARN is on the request path, once per such request. Lifecycle Create, Sleep, Wake, Close, bound, and unbound stay off the request path.

Traefik instantiates every middleware in one publish before the new routers receive traffic. Constructor order inside that publish can still run the bouncer `New` before the owner `New`. No request arrives in that gap. When the owner is in the same publish and its `New` succeeded, Publish has already stored the client into the subscriber, so the first request is bound. The WARN is a subscribed name that no live publisher holds after that publish, such as a name nobody opens.

A subscriber never reads `crowdsecMode` (the published client already has a fetch strategy). A subscriber never **Bind**s reclaim. Unsubscribe does not release the backend. Opener settings on a leg that does not open are ignored. Mode, host, scheme, path, scopes, intervals, `updateMaxFailure`, CAPI, Redis, TLS, timeout, and `defaultDecisionSeconds` do not fail `New` and do not change the published client.

### Holder and subscriber

The backend is one LAPI Client or one AppSec Client. The **ownership key** is the Traefik middleware name plus the whole settings block for that leg. A second middleware with the same LAPI settings and a different name is a different ownership key and a different Client. The Client `Sleep`s only when that ownership key’s last constructor context is gone.

The bouncer, the LAPI owner, and the AppSec owner can sit on the same middleware. Each is its own piece. The bouncer subscribes by slot name and does not use the ownership key. Each owner opens its own client. Owning LAPI does not subscribe that middleware to AppSec, and owning AppSec does not subscribe it to LAPI. `enabled: true` subscribes the bouncer to `crowdsecLapiInstanceName` after prepopulation. That prepopulation runs only when `crowdsecLapiEnabled` is true. `crowdsecAppsecInstanceName` is prepopulated only when `crowdsecAppsecEnabled` is true. `enabled: false` does not subscribe. Zero subscribers does not drop an owner. `New` is still one constructor. If any piece fails, including a rejected publish, `New` returns the error and every piece on that constructor fails with it. That is intentional.

### Reclaim (slot name vs opener settings)

Bouncers subscribe to the **instance name**. They must not Bind reclaim. The holder is the owning middleware (settings + that middleware’s name). If subscribers Bind, the stream stays alive after that owner is gone.

Name-only reclaim is **not** enough. If the key is just the name, a reload that changes HTTP timeout, TLS, or even the LAPI/AppSec **host** Wakes the old Client and the new settings never apply.

Split:

| | Key | Job |
|---|---|---|
| Slot (Publish / Subscribe) | leg + instance name | What bouncers bind to. LAPI and AppSec are separate tables. `shared` in one does not occupy `shared` in the other. Not an ownership key. |
| LAPI ownership `Open` | middleware name **+** mode, scheme, host, path, key, TLS, effective HTTP timeout, Redis, `crowdsecLapiStreamScopes`, CAPI machine id and password, `updateIntervalSeconds`, `metricsUpdateIntervalSeconds`, `updateMaxFailure`, `crowdsecCapiScenarios`, `defaultDecisionSeconds` | One LAPI Client per owning middleware. Same middleware name and same settings Wake on reload. A different middleware name is a different Client even when the settings match. `streamStartupBlock` is not in this key. |
| AppSec ownership `Open` | middleware name **+** scheme, host, path, resolved key, body limit, TLS (insecure verify, CA, bouncer cert, bouncer key), effective HTTP timeout | One AppSec Client per owning middleware. Same rule as LAPI. No decision store, so nothing is shared with another middleware. |
| DecisionStore | `SessionHex` (mode, scheme, host, path, API key, CAPI machine id and password, `defaultDecisionSeconds`, for stream the canonical scope list, and the Redis block only when `redisCacheEnabled` is true) | LAPI only. One store per that identity. Not the middleware name. Not the slot name. Two LAPI ownership keys that share a `SessionHex` write this store. |

`updateIntervalSeconds`, `metricsUpdateIntervalSeconds`, `updateMaxFailure`, and `crowdsecCapiScenarios` are on the LAPI client only. A change is a new Client and the same `SessionHex` when the rest of the store identity matches. `Wake` on the old Client would keep the old ticker, the old failure threshold, and the old CAPI scenario list, because those values are copied at `New`. The new Client polls, counts failures, and logs in with its own values. `defaultDecisionSeconds` is on the client and in `SessionHex`. Live lookups write that TTL into the store (`min(decision duration, defaultDecisionSeconds)`). A change is a new Client and a new store, so the old TTLs are not reused. The bouncer does not pass its own TTL into `LiveLookup`.

`streamStartupBlock` stays on the bouncer. The client does not read it, and `Open` does not block on the first poll. Blocking `New` deadlocks. On the request path, `true` asks whether every backend this bouncer subscribes to is ready. A bouncer subscribed to one backend checks only that one. A backend it does not subscribe to is not part of the question. For this change, ready means that subscribed client is published. It does not mean the first poll has finished. While any subscribed client is not published, `ServeHTTP` returns 503, does not call `next`, and does not use that leg's failure action. Once every subscribed client is published, requests follow the normal path even if a first poll is still in flight. `false` does not ask that question: a missing subscribed client uses that leg's failure action. The flag is not in the ownership key and not in `SessionHex`. What "ready" should mean beyond "the client is published" is still open in `knowledge/debt/2026-09-22-stream-startup-block-rethink.md`. The knob's name still says stream startup.

A bouncer subscribed to both LAPI and AppSec applies both guards on each request. One published backend does not stand in for the other. The subscribe shape is `enabled: true` and the instance name set. An omitted name is prepopulated to this Traefik middleware name only when that leg's owner flag is true, so an owner that also bounces matches. A leg whose flag is false and whose name was left unset is not subscribed. While `streamStartupBlock` is true, a request is 503 until every subscribed client is published. A bouncer subscribed only to AppSec does not 503 for a missing LAPI client. `New` has already returned.

The instance name, `enabled`, `decisionScopeHeaders`, and `crowdsecAppsecFailureAction` are not in either ownership key. The effective HTTP timeout is `crowdsecLapiHttpTimeoutSeconds` or `crowdsecAppsecHttpTimeoutSeconds` when that override is set, otherwise `httpTimeoutSeconds`. Resolved key and TLS material are hashed, so the same secret from a file or from the inline field is the same client. `AdoptTransport` does not apply an AppSec timeout or TLS change. That change is a new ownership key and a new Client. A different middleware name is a different ownership key, even with the same settings. A settings change on one middleware is a new Client for that name. The old Client is not Woken. `Sleep` stops the ticker when that ownership key’s last context is gone; grace `Close` only drops idle sockets. Two ownership keys that still match `SessionHex` write the same store. `TryBeginStreamPoll` keeps one GET in flight. If the new client's startup poll skips because the old ticker still holds that lock, it polls again when the lock is free instead of waiting a full `updateIntervalSeconds`.

Two stream or alone owners with the same LAPI host and API key are unsupported. `New` still succeeds for both. The second `Open` logs one WARN, `msg` `crowdsec lapi stream collision`, with both middleware names and the host. It does not log the API key. Live and none do not emit it. A subscriber does not emit it. Real e2e builds this file and asserts that line in `docker logs traefik-test`. The routes still answer. The `createdBy` Peek that fails `New` is removed. When `redisCacheEnabled` is false, `SessionHex` includes no Redis fields, so a leftover host, read hosts, password, or database does not change the store. When it is true, `SessionHex` includes the whole set: host, read hosts sorted, password, and database. Turning Redis on or off, or changing any of that set, is a new store. The new store is not `StreamReady`, so the first poll is `startup=true` and fills that engine. The old store is left behind until its own client finishes grace.

Two overlapping incarnations of the same `SessionHex`: the dying Client must not Close the store. A host or API key change is a new `SessionHex` and a new store.

### Replace while the old Client is in grace (A–D)

Traefik ends the old constructor context **before** it calls `New` for the replacement. Same client-behavior settings: the last holder’s end `Sleep`s the Client, and the new `Open` `Wake`s it inside grace. The Client does not `Close`. A behavior change is a new reclaim key: the old Client stays asleep until grace `Close`, and the new `Open` Publishes the new pointer.

```
  same settings
  ─────────────
  (1) old ctx ends ── last holder ── Sleep(P)
  (2) new New ── Open(same key) ── Wake(P)
      subscribers already hold P; nothing is cleared

  behavior change
  ───────────────
  (A) opener YAML changed (timeout, TLS, host, …)
  (B) old ctx ends ── Sleep(client A)     # ticker stopped; grace running
  (C) new New ── Open(new key) ── Publish(name, client B)
      subscribers Store(client B)
  (D) later, A Close after grace:
        if slot.current == A  → Clear: Store((*Client)(nil))
        if slot.current != A  → no-op
```

Clear is **generation-aware**: it takes the dying `*Client` (or a gen id), not only the name. `Clear(name)` that always stores a typed nil is the bug: (C) then old Close would unbind bouncers from B. `atomic.Value.Store(nil)` panics. The empty value is a typed nil, `(*lapi.Client)(nil)` or `(*appsec.Client)(nil)`. The first `Store` on that `atomic.Value` fixes the type, so Publish and Clear use the same pointer type.

The hold is the constructor context, which is what reclaim already does. Releasing by middleware name would be wrong on a different order. On this order the old context is already gone before the new `Open`, so a same-key reload is `Sleep` then `Wake` of one Client.

- **Replacement (A–C).** Bouncers do not listen for A’s Close. Publish of B is the switch. Until that Publish they still hold sleeping A and keep serving it. That gap is short and acceptable.
- **No replacement (D).** Subscribers are not holders. Dropping every subscriber leaves the Client up while its owning middleware still exists, including `enabled: false`. The Client `Sleep`s when its last holder is gone. On grace `Close`, every slot whose `current` is still that dying pointer stores a typed nil. A slot that already Published a replacement is left alone.

The middleware does not remember the previous slot name. The new configuration only has the new name, and the old constructor is already gone.

A **new** Client does not need that memory. The old Client is asleep with no holder. Its grace `Close` unpublishes every slot whose `current` is still that old pointer. Subscribers of the old name keep the sleeping Client until that `Close`, then miss. They are not moved to the new name.

The **same** Client does need it. `Close` will not run, so both names would keep pointing at it. The Client stores the slot name it last published. `Wake` reads that. When it differs from the name in the new configuration, unpublish the stored name before publishing the new one. Unpublish clears that slot only when `current` is still this Client and the slot's recorded publisher is this middleware. Then store the new name on the Client. The same name publishes again and does not unpublish. `Sleep` leaves the stored name in place so the following `Wake` can read it. A first `Open` has no stored name. LAPI and AppSec each store their own.

Every slot records the middleware name that published it, next to `current`. There are two slot tables. A LAPI publish looks only at the LAPI table, and an AppSec publish looks only at the AppSec table. One middleware can hold LAPI `shared` and AppSec `shared` at the same time. A taken name does not cross tables. Unpublish is a no-op unless the caller is the recorded publisher in that table. A different middleware cannot clear the slot on rename or on `Close`.

There is no name check before `Open`. A leg this `New` would publish is one with `crowdsecLapiEnabled` or `crowdsecAppsecEnabled` true, and it is opened first. `enabled: true` subscribes to the instance name after that prepopulation. A leg whose flag is false is not opened, and an unset name on that leg is not prepopulated. Held by the owner is what that subscriber wants.

`New` receives Traefik's constructor context and does not receive its cancel function. Every `Open` in that `New` takes one child, `context.WithCancel` of the constructor context. On success the child is left running; it ends when Traefik cancels the parent, which is the normal Sleep. On any failure after an `Open`, including a rejected publish, `New` calls that cancel and returns the error. One cancel drops every hold this `New` took. The clients Sleep, and grace `Close` follows. Cancelling Traefik's own context is not possible from inside `New`.

Publish is the rejection, and it runs under the slot mutex after those Opens. Publish onto a name already held by another middleware in that same table does not replace `current` and does not change the recorded publisher. The same middleware publishing again, including a new Client pointer after a settings change, is allowed: it is the recorded publisher. Two simultaneous `New`s may both Open. The mutex lets only one of them publish that slot. The other gets the error, cancels its child, and does not subscribe or bounce.

When this `New` publishes more than one leg, those publishes share one mutex section. If any of them is rejected, every slot this attempt already wrote is unpublished before the mutex is released, then the child is cancelled. A free LAPI name must not stay published when the AppSec name in the same `New` is taken. `ServeHTTP` only Loads, so a request in the gap between that store and the clear can use the client that is about to Sleep. After the clear the subscriber is empty again. That gap is acceptable.

The error names the middleware that already published that slot and says that name has to be released first. One ERROR is logged, `msg` `crowdsec instance name taken`, with `leg`, `instanceName`, the publisher middleware name, and the rejected middleware name. The API key is not in the line. The rejected route does not answer. Its client was opened, then put to sleep by the cancel; the log can show `instance started` and then `instance sleeping` for that incarnation. A slot this attempt wrote and then cleared can `bound` and then `unbound` in that gap. After the clear, subscribers are not left on that client. After the holder releases the name, a later `New` of the rejected middleware can take it. Nothing retries the failed `New` until Traefik constructs that middleware again.

A rename onto a taken name is the same rule. Traefik has already cancelled the old constructor, so that client is asleep. The new `Open` may Wake it when the ownership key matches, then the publish is rejected and the child cancel puts it back to sleep. The failed `New` does not keep the old slot. Grace `Close` unpublishes the old name. The subscriber loses that backend. No replacement is published. That is acceptable.

### Mode

`crowdsecMode` is how a LAPI **opener** fetches decisions (`live` \| `stream` \| `none` \| `alone`). It is not how the bouncer bounces, and it is not “which legs this middleware runs.”

`crowdsecMode: appsec` goes away. It meant: no LAPI client on this middleware, AppSec only. That is now:

```yaml
crowdsecLapiEnabled: false
crowdsecAppsecEnabled: true
```

`crowdsecMode` is ignored when LAPI is disabled.

The Client owns `crowdsecMode`. `ServeHTTP` reads it from the LAPI client loaded on that request. A nil client has no mode; that leg uses the router's failure action. A Publish that swaps a stream client for a live client changes the branch on the next request. The bouncer does not copy the mode at `New`.

### Stream scopes

`decisionScopeHeaders` stays bouncer configuration: CrowdSec scope name to request header name. `ServeHTTP` extracts with that map. Header names are not sent to LAPI.

`crowdsecLapiStreamScopes` is opener configuration: the extra scope names the LAPI stream poll follows (`country`, `as`, …). `ip` and `range` are always on the poll. An omitted or empty list means `scopes=ip,range` only. Nothing is copied from `decisionScopeHeaders`. Live and none ignore the list. CAPI (alone) has no `scopes=` parameter, so the list is LAPI stream only.

A bouncing middleware, including an all-in-one opener, warns once when it binds to a client whose list does not cover the keys of its `decisionScopeHeaders`. The same check runs again when Publish swaps in a new client. A nil client has nothing to compare. The warning names the middleware and the missing scopes. It is not on the request path. A subscriber does not carry `crowdsecLapiStreamScopes`.

The store keeps decisions for scopes the list asked for, including while no bouncer is extracting them yet. The canonical list is part of `SessionHex` in stream mode: `ip` and `range`, then the extra names, sorted, so order in YAML does not matter. Omitted and empty hash the same. Live, none, and alone leave that field empty. A list change is a new store, not a reclaim of the old one. The new store is not `StreamReady`, so `New` keeps `startup=true` and the first poll refills it. The same list still reclaims the warm store and stays `startup=false`.

### Late bind (coordination)

`ServeHTTP` does **not** resolve instance names, Peek a table, or Open a client. Bounce uses whatever is already on the middleware: **two optional** bound clients, each an `atomic.Value` — LAPI and AppSec. Either may be **empty** on its own (LAPI-only, AppSec-only, both, or neither). Empty means a typed nil. With `streamStartupBlock` true, any subscribed client that is not published yet is a **503** for the request. A client this bouncer does not subscribe to is not part of that check. With the flag false, a missing subscribed client is that leg's failure action. A live client with no decision is still an allow when the stream is healthy. We do not require a live client when the request arrives, and we do not wait for one inside `New`.

Bind happens **off** the request path.

```
  opener New  ──Open──► Publish(name, client)     // slot.current = this pointer; Store on subscribers
  opener Client Close (after grace) ──Clear(name, dying)
       slot.current == dying  → empty + Store(typed nil)   // D: no replacement
       slot.current != dying  → no-op                // C: already switched to the new Client

  bouncer New  ── Subscribe(lapiName, &bouncer.lapi) and/or Subscribe(appsecName, &bouncer.appsec)
                 lock, append this atomic to that leg’s slot, copy current (maybe nil), unlock
                 return immediately (never wait)
  bouncer ctx done ── Unsubscribe so Traefik reload does not leak the old middleware

  bouncer ServeHTTP ── Load bouncer.lapi and bouncer.appsec
       enabled leg empty / Closed  → that router’s failure action for that leg
       live                        → use it
```

**Grab.** Subscriber `New` can return first. That leg’s bound field stays empty until the opener Publishes. Publish copies the pointer into each registered `atomic.Value` on the opener’s `New` (sync, no goroutine). A publish that contains both does not serve the new routers until every middleware in it has finished `New`, so the first request already has that client. A request sees an empty field when the live config has no publisher for that name. A bouncer subscribed to both LAPI and AppSec applies both guards on each request. A missing LAPI client with `streamStartupBlock: true` is 503 for the whole request, including when AppSec is already published.

**Drop.** The last opener of a client key is gone: grace `Close` stores a typed nil on every slot whose `current` is still that pointer and whose recorded publisher is this middleware. Same miss as “not published yet.” A slot published by someone else is not cleared.

**Replace.** The old context has already ended. Same key: `Wake` the sleeping Client. New key: `Publish` B, then old `Close` is a no-op for the slot when `current` is already B. Subscribers must not Bind reclaim.

A process-wide **channel** is the wrong push primitive: unbuffered send is 1:1 (one consumer), and send from opener `New` with nobody receiving yet blocks construct. Fan-out is a **subscriber list of `*atomic.Value`** on the named slot (Yaegi-safe; not `atomic.Pointer[T]`, not `func` callbacks). Publish and Clear take the slot mutex, and both the `slot.current` update and the subscriber `Store`s happen before that unlock. Dropping the mutex before `Store` lets Clear write nil over a Publish that already stored the replacement. `Store` on an `atomic.Value` is not foreign code. Sleep does not clear the slot. Clear runs on grace `Close` of a Client, and only on slots whose `current` is still that dying pointer and whose recorded publisher is that Client's middleware. A middleware that did not publish cannot unpublish. Subscribers are not holders. An empty subscriber list does not `Close` the Client. The only extra goroutine is Unsubscribe on the **bouncer’s** `ctx.Done()` (teardown, not notify).

All-in-one middleware (opens and bounces): Open then Publish, including Store onto its own bound fields in the same `New`. No wait. Requests do not hit the new routers until every middleware in that publish has finished `New`.

### Lifecycle logs (e2e grep contract)

HTTP status is not enough to prove A–D. Traefik stdout (`docker logs traefik-test`) MUST show the internals in order. Do not log them on the request path. Operator default: Create, Close, bound, unbound at INFO. Sleep/Wake stay DEBUG so a production INFO log is not full of Traefik reconstruct noise. Real e2e **may set plugin `logLevel` to DEBUG or TRACE** for lifecycle cases — that is acceptable.

**Backend** (LAPI Client and AppSec Client, each incarnation). Create is the reclaim `create` hook. Sleep / Wake / Close are the reclaim hooks (same four events as today’s connection / decision-store lines).

| Event | Level | Stable `msg` | When |
|---|---|---|---|
| Create | INFO | `crowdsec lapi instance started` / `crowdsec appsec instance started` | `create` ran (new reclaim key) |
| Sleep | DEBUG | `… instance sleeping` | last holder gone, grace running |
| Wake | DEBUG | `… instance waking` | same reclaim key Open during grace |
| Close | INFO | `… instance closed` | grace ended, this incarnation disposed |

Required attrs on every backend line: `leg` (`lapi`\|`appsec`), `instanceName` (slot), `incarnation` (reclaim key or a short id unique per create). Two overlapping Clients of `shared` MUST differ on `incarnation` so grep can tell A from B.

**Bouncer** (each bouncing middleware, per enabled leg). Emit only when the bound `atomic.Value` **changes**, never per request.

| Event | Level | Stable `msg` | When |
|---|---|---|---|
| Bound | INFO | `crowdsec bouncer bound` | `Store` of a non-nil `*Client` (Publish, including replace A→B) |
| Unbound | INFO | `crowdsec bouncer unbound` | `Store` of a typed nil (Clear of **this** incarnation), or subscriber `New` while the slot is empty |

Required attrs: `traefikName`, `leg`, `instanceName`, and `incarnation` (the pointer just stored, or the pointer just cleared). Same-slot replace of A by B is `bound` A then `bound` B with no `unbound`. A rename of the same Client is different: `unbound` on the old `instanceName` comes before `bound` on the new `instanceName`, and both lines carry that Client’s `incarnation`. `unbound` is also the no-replacement path (D), when grace `Close` clears a slot that still points at the dying Client.

Placeholder (`enabled: false`) still logs backend Create/Sleep/Wake/Close. It does not log bouncer bound/unbound (it does not bounce). An all-in-one opener that also bounces logs both.

---


### Placeholder

Traefik only calls `New` if a router is attached. Opening is independent of bouncing: secrets + `crowdsecLapiEnabled` / `crowdsecAppsecEnabled` still publish clients when `enabled` is `false`. Requests that hit that router call `next`.

A dummy router is **optional**. Use it only when no bouncing route should own the clients. Attach it to some rule so `New` runs; keep that rule off real traffic if you do not want origin served there. No extra hold flag.

### Fetch vs bounce knobs

On the **opener**: LAPI host/key/mode, Redis, `crowdsecLapiStreamScopes` (what the LAPI stream poll asks for), AppSec host/key/body limit, TLS, HTTP timeout.

On the **bouncer** (including the all-in-one middleware): remediation header/status, failure actions, captcha, trusted IPs, remap-when-it-exists, `decisionScopeHeaders` (which request headers this route looks up).

Subscribers do not union their header map into `scopes=`. The poll follows the opener list only. A bouncer whose map needs a scope that list does not name warns at bind. The DecisionStore key is `SessionHex`, shared by every client on that cursor, including two slot names. The slot name is only what bouncers subscribe to.

---

## Config surface (existing prefixes)

New fields only. Everything else stays as it is today.

| Field | Default | Job |
|---|---|---|
| `crowdsecLapiEnabled` | `false` | This middleware manages a LAPI client (open or subscribe). Omitted = the leg is off. `enabled` does not turn it on. `true` replaces nothing by itself; `crowdsecMode: appsec` went away because LAPI-off is this flag left false. |
| `crowdsecLapiInstanceName` | empty = Traefik name | Slot to Open or subscribe |
| `crowdsecAppsecEnabled` | `false` (already exists) | This middleware uses the AppSec leg |
| `crowdsecAppsecInstanceName` | empty = Traefik name when AppSec is enabled | Slot to Open or subscribe |
| `enabled` | `false` (already exists) | Bounce switch. `true` applies decisions. `false` calls `next`; Open still runs if this middleware has secrets. |
| `crowdsecLapiStreamScopes` | empty | Extra LAPI stream scopes (`country`, `as`, …). Omitted or empty = `ip,range` only. Not copied from `decisionScopeHeaders`. Opener only. |

`crowdsecMode`: `live` \| `stream` \| `none` \| `alone`. Remove `appsec`. The bound LAPI client owns the value `ServeHTTP` branches on.

---

## YAML (the setups we walked)

One router, same as today. Names omitted, so it publishes under its Traefik name and bounces.

```yaml
api-crowdsec:
  plugin:
    bouncer:
      crowdsecMode: stream
      crowdsecLapiEnabled: true
      crowdsecAppsecEnabled: true
      crowdsecLapiHost: crowdsec:8080
      crowdsecLapiKey: "..."
      crowdsecAppsecKey: "..."
      enabled: true
```

Several routers, one pair of clients. The owner is a **real** route; nothing is a dummy.

```yaml
# Opens both slots and bounces /api
cs:
  plugin:
    bouncer:
      crowdsecMode: stream
      crowdsecLapiEnabled: true
      crowdsecAppsecEnabled: true
      crowdsecLapiInstanceName: shared
      crowdsecAppsecInstanceName: shared
      crowdsecLapiHost: crowdsec:8080
      crowdsecLapiKey: "..."
      crowdsecAppsecKey: "..."

# Only bounces /admin. Per-route knobs live here.
cs-admin:
  plugin:
    bouncer:
      enabled: true
      crowdsecLapiEnabled: true
      crowdsecAppsecEnabled: true
      crowdsecLapiInstanceName: shared
      crowdsecAppsecInstanceName: shared
      remediationHeadersCustomName: x-crowdsec
```

AppSec only, no LAPI.

```yaml
waf:
  plugin:
    bouncer:
      crowdsecLapiEnabled: false
      crowdsecAppsecEnabled: true
      crowdsecAppsecHost: crowdsec:7422
      crowdsecAppsecKey: "..."
```

Placeholder, only when no bouncing route should own the clients.

```yaml
cs-holders:
  plugin:
    bouncer:
      enabled: false
      crowdsecMode: stream
      crowdsecLapiEnabled: true
      crowdsecAppsecEnabled: true
      crowdsecLapiInstanceName: shared
      crowdsecAppsecInstanceName: shared
      crowdsecLapiHost: crowdsec:8080
      crowdsecLapiKey: "..."
      crowdsecAppsecKey: "..."
```

---

## Required test coverage (real-stack e2e)

These cases honour the design against **Traefik’s constructor, file-provider reload, and reclaim grace**. They live in `tests/e2e/real/` (Pester + Docker Traefik + live Crowdsec), not `tests/e2e/mock/` and not `go test` of the slot table.

Mock e2e and unit tests can pin helpers. They cannot prove unordered `New`, overlapping reload, or `ProcessGrace` (30s) `Close` while another incarnation is already Published. A–D are Pester or they are untested. The DecisionStore Redis cases (S1–S5), the AppSec ownership cases (P1–P4), and the LAPI client-knob cases (I1–I3) are `go test`; they do not need Traefik.

### Harness

- Drive named slots through the **file provider** (nested maps and reloads). Today `dynamic-scopes.yml` is mounted `:ro`; reload cases need a **writable** watched file (or directory) the test can rewrite, then wait until Traefik has applied it (probe the route, not a sleep-only).
- Identify the client with `X-Forwarded-For`. Ban with `cscli` as the rest of this suite.
- Empty / missing backend is visible via that router’s `crowdsecLapiFailureAction` / `crowdsecAppsecFailureAction` (`passthrough` → 200, `ban` → 403). Point a “dead” opener at `crowdsec:9` with a short `httpTimeoutSeconds` (existing fail-action pattern). Do not `docker pause` Crowdsec.
- Lifecycle cases: set plugin `logLevel` to **DEBUG or TRACE** so Sleep/Wake are in `docker logs traefik-test`. Create/Close/bound/unbound are INFO and show at either. Snapshot logs before the rewrite, then assert **order** of `msg` + `instanceName` + `incarnation` (and `traefikName` on bouncer lines).
- After a settings change, wait long enough to cover **grace Close** of the old Client (`ProcessGrace` 30s plus a small margin) where the case cares about (C) vs (D).
- Isolation: two **opener names** that would share mode+host still need distinct LAPI keys unless the case is the collision WARN itself. Subscribers share the owner’s key by not sending one.

Suggested file: `tests/e2e/real/instance_severance.Tests.ps1`.

### Cases

**Topology (static YAML, no reload)**

| Id | Honour | Setup | Expect |
|---|---|---|---|
| T1 | One middleware still valid | Names omitted; stream + AppSec on; bounce default true. Ban IP. | `/` path 403. Same shape as today’s `/whoami`. |
| T2 | Named share, owner is a real route | Opener+bounce on `/api` (`crowdsecLapiInstanceName` / `crowdsecAppsecInstanceName: shared`). Subscriber-only on `/admin` with a different `remediationHeadersCustomName`. Ban IP. | Both paths 403. `/admin` carries the subscriber header, `/api` does not. No `crowdsec instance name taken`. LAPI `bound` and AppSec `bound` are both `instanceName=shared` and their incarnations differ. |
| T3 | Optional placeholder | Opener `enabled: false` on a dummy path; subscriber on `/app`. Ban IP. | Dummy path 200 (`next`). `/app` 403. |
| T4 | `crowdsecLapiEnabled: false` replaces `mode: appsec` | AppSec-only middleware, no LAPI name, no LAPI key. `crowdsecAppsecEnabled: true` with an AppSec key. `streamStartupBlock` left at the default. CRS SQLi vs clean. | The bouncer subscribes only to AppSec. SQLi 403, clean 200. No LAPI 503. |
| T5 | Per-route bounce knobs | Two subscribers to `shared`. Different `crowdsecLapiFailureAction` is unused here; different remediation status or header. Ban IP. | Same decision, different bounce surface. |

**Late bind (constructor order, no Peek on the request path)**

| Id | Honour | Setup | Expect |
|---|---|---|---|
| L1 | A publish with no opener | Write a file with **only** subscribers. `streamStartupBlock: true` (the default). That publish finishes, then probe. Then add the opener in a second publish. Ban IP. | After the first publish: **503**, and `crowdsec bouncer backend missing`. `New` returned. Traefik did not deadlock. A single publish that already contains the opener does not get a request between the two `New`s; the first request is bound. After the opener’s publish: 403 from the decision, even if the first poll has not finished. |
| L1b | Subscriber `New` first, startup block off | Same as L1 with `streamStartupBlock: false` (`passthrough` on A, `ban` on B). | Before opener: A 200, B 403 (that router’s failure action). After opener is up: both 403 from the decision. |
| L2 | Enabled leg with no backend (misconfig) | Subscriber points at `missing`. Never Open that name. One router `streamStartupBlock: true`, one `false` with `crowdsecLapiFailureAction: ban`. | The `true` router stays **503**. The `false` router stays 403. Not 500 from a nil deref. |
| L3 | Two subscribed clients, one missing | Shared LAPI live; AppSec instance name that nobody Opens; subscriber subscribes to both; `streamStartupBlock` left true. Ban IP. SQLi. | Both requests are **503** until AppSec is published, because the bouncer subscribed to both. With `streamStartupBlock: false` and AppSec failure `passthrough`: ban still 403 (LAPI), SQLi is not extra-blocked. |
| L4 | Mixed bind over time | LAPI opener up, AppSec opener added later (second rewrite). | LAPI remediates immediately. AppSec miss uses AppSec failure until the AppSec opener Publishes, then CRS applies. |

**Reclaim and reload (A–D)** — these are the ones that require real Traefik.

| Id | Honour | Setup | Expect |
|---|---|---|---|
| R1 | Same name + same settings Wakes | Named opener+subscriber. Ban IP (403). Rewrite the **same** YAML (touch / rewrite identical opener knobs) so Traefik reconstructs. | Still 403 through reconstruct and through 30s+ grace. No window of failure-action on the subscriber. |
| R2 | Same name + settings change is a new Client (A–C) | Stream opener `shared`. Subscriber `crowdsecLapiFailureAction: passthrough`. Ban IP (403). Rewrite opener host to `crowdsec:9`, keep instance name `shared`. | Before the subscriber’s bound line for the new client: still 403 from the sleeping client. That gap is acceptable. After that bound line and before grace Close: 200 (empty new store, startup poll already failed, passthrough). After grace: still 200. |
| R3 | HTTP timeout or TLS is a new Client, same store | Stream opener `shared`. Subscriber banned (403). Rewrite only the effective LAPI HTTP timeout, or only the LAPI TLS material. Host, API key, scope list, and Redis stay the same. Plugin `logLevel` DEBUG. | One incarnation A sleeps and does not wake. A new incarnation B starts, then the subscriber is `bound` to B, same `instanceName`. The ban stays 403. After grace, A is `closed` and the subscriber is not `unbound`. |
| R4 | Slot rename, same Client | Opener+subscriber on `shared`. Ban 403. Rewrite only the opener’s instance name to `other`. Leave the subscriber on `shared`. `streamStartupBlock: true`. | Status alone is not the proof. N1’s log order is. After that order, the subscriber of `shared` returns **503**. A subscriber of `other` stays 403. |
| R5 | Subscribers must not Bind reclaim | Opener+subscriber. Ban 403. **Delete** the opener middleware from the file; keep the subscriber. `streamStartupBlock: true`. | After grace, the tail of N2: `instance closed` for that incarnation, then `bouncer unbound` for the subscriber, then **503**. No `waking`. Stream must not stay alive on the subscriber’s ctx. |
| R6 | DecisionStore stays with `SessionHex` | Two overlapping incarnations of `shared` that keep the same host and API key (timeout or TLS change, not R2's host change). cscli ban. | Replacement still sees the decision (dying Client must not Close the store). A host or API key change is a new store. After Publish the old ban is gone; during the gap the subscriber still serves it from the sleeping client. |

**Slot name versus new backend (real e2e, log order)** — HTTP status is not enough. These two reloads look alike if you only watch 403 and 503. Plugin `logLevel` is DEBUG. Snapshot `docker logs traefik-test` before the rewrite. Assert `msg` order with `leg`, `instanceName`, and `incarnation`. Same script for AppSec (`leg=appsec`, `crowdsec appsec instance …`).

| Id | Setup | Log order after the rewrite |
|---|---|---|
| N1 | Same Client, new slot name. Opener publishes `shared`. Subscriber `cs-admin` stays on `shared`. A second subscriber uses `other` only after the rewrite. Rewrite **only** the opener’s instance name from `shared` to `other`. | One `incarnation` I. `crowdsec lapi instance sleeping` then `crowdsec lapi instance waking`, both I. Then `crowdsec bouncer unbound` for `cs-admin` with `instanceName=shared` and I, **before** `crowdsec bouncer bound` for the `other` subscriber with I. No second `crowdsec lapi instance started`. No `crowdsec lapi instance closed` for I in this window. `cs-admin` then returns 503. |
| N2 | New Client and new slot name. Opener publishes `shared`. Subscriber `cs-admin` stays on `shared`. Rewrite the opener to a new host (`crowdsec:9`) **and** instance name `other`. A subscriber of `other` is in that same rewrite. | `crowdsec lapi instance sleeping` for incarnation A. Then `crowdsec lapi instance started` for a different incarnation B with `instanceName=other`, and `crowdsec bouncer bound` for the `other` subscriber with B. No `waking` for A. No `unbound` for `cs-admin` yet: it still holds A. After grace: `crowdsec lapi instance closed` for A, then `crowdsec bouncer unbound` for `cs-admin` with `instanceName=shared` and A. No `unbound` for `other` or B. |

**Two owners, one slot name (real e2e)** — the second `New` fails. The first publisher's route still serves.

| Id | Setup | Expect |
|---|---|---|
| F1 | Two middlewares, `cs-a` and `cs-b`, both `crowdsecLapiEnabled: true`, both `crowdsecLapiInstanceName: shared`, distinct API keys. A subscriber of `shared`. Then release the name (`cs-a` removed or renamed) and rewrite `cs-b` so Traefik constructs it again. | The subscriber follows whichever middleware published first. The other router's `New` fails after `Open`. `docker logs traefik-test` contains `crowdsec instance name taken` at ERROR with `instanceName=shared`, the publisher middleware, and the rejected middleware. The API key is not in the line. The rejected middleware also logs `instance started` and then `instance sleeping` for its own incarnation. The rejected route does not answer. The subscriber is not rebound to that incarnation. After the name is released and `cs-b` is constructed again, `cs-b` publishes and the subscriber can bind to it. The same shape with AppSec (`leg=appsec`) is required. |
| F2 | `waf` already publishes AppSec `waf`. Add `cs` with a free LAPI name `api` and AppSec name `waf`, both enabled, both with their own keys. A subscriber of LAPI `api`. | `cs` does not answer. Both clients are opened, then the AppSec publish is rejected and the child context is cancelled, so both sleep. The log contains `crowdsec instance name taken` with `leg=appsec` and `instanceName=waf`, plus `crowdsec lapi instance started` and `crowdsec lapi instance sleeping` for `cs`. A request in the store/clear gap may use the LAPI client; that is acceptable. After the clear, the subscriber of `api` is not left `bound`. |
| F3 | Owner already publishes LAPI `shared` and AppSec `shared`. Add `cs-admin` with both legs enabled, both instance names `shared`, and no LAPI key and no AppSec key. | `cs-admin` answers. No `crowdsec instance name taken`. It is `bound` to the owner's clients. |

**DecisionStore identity (go test, not Pester)**

`SessionHex` and which store `Open` returns are provable without Traefik. These live next to `pkg/lapi/zzz_session_test.go`. `TestOpenStream_SleepingRedisHostDoesNotOverlapPollers` currently asserts the opposite (a Redis host change keeps the same store) and is replaced by S3.

| Id | Honour | Setup | Expect |
|---|---|---|---|
| S1 | Redis off is not part of the store | `redisCacheEnabled: false` on both. Second config fills host, read hosts, password, and database. Same LAPI settings. Cancel, then `Open` again. | Same `SessionHex`. Same store. |
| S2 | Read-host order does not fork the store | `redisCacheEnabled: true`. Same host, password, and database. Read hosts listed in opposite order. | Same `SessionHex`. Same store. |
| S3 | A Redis change is a new store | `redisCacheEnabled: true`. First `Open` polls once (`StreamReady`). Cancel. Second `Open` changes one of host, password, database, or read-host membership. Repeat once per field. | Different `SessionHex`. Different store. New client sends `startup=true`. Old client’s ticker stays asleep. |
| S4 | Turning Redis on or off is a new store | First `Open` with `redisCacheEnabled: false`. Cancel. Second with `true` and a host. Then the reverse, true then false. | Different `SessionHex` each way. Different store. The new client sends `startup=true`. |
| S5 | Same Redis set reclaims | `redisCacheEnabled: true`. Same host, read hosts, password, and database. Cancel, then `Open` again. | Same `SessionHex`. Same store. `startup=false`. |

**AppSec ownership (go test, not Pester)**

These live next to `pkg/appsec/zzz_session_test.go`. `TestOpen_ReclaimsSameClient` currently asserts two middleware names share one Client and is replaced by P1. `TestOpen_TimeoutOnlyAdoptsTransport` currently asserts a timeout change reuses the Client and is replaced by P2.

| Id | Honour | Setup | Expect |
|---|---|---|---|
| P1 | Middleware name is part of the key | Two `Open` calls, distinct middleware names, identical AppSec knobs. | Two Clients. |
| P2 | Any AppSec knob change is a new Client | Same middleware name. Second `Open` changes one of scheme, host, path, key, body limit, TLS, or effective HTTP timeout. Repeat once per field. | Different Client. `AdoptTransport` is not how the new value applies. |
| P3 | Same middleware and same knobs Wake | Same middleware name and the same AppSec knobs. Cancel, then `Open` again. | Same Client. |
| P4 | Omitted AppSec scheme follows LAPI | Same AppSec host, path, key, body limit, TLS, and timeout. `crowdsecAppsecScheme` omitted. Second config sets `crowdsecLapiScheme: https`. A third sets `crowdsecAppsecScheme: https` and leaves the LAPI scheme at `http`. | The first client uses the LAPI scheme `http`. The second and third are the same AppSec Client key, scheme `https`. |

**LAPI client knobs (go test, not Pester)**

These live next to `pkg/lapi/zzz_session_test.go`. The test that says `updateIntervalSeconds` must not split the stream open key is replaced by I1. `TestSessionKey_PolicyAndTLSDoNotChangeKey` must stop treating `defaultDecisionSeconds` as ignored. `streamStartupBlock` stays out of both keys.

| Id | Honour | Setup | Expect |
|---|---|---|---|
| I1 | Interval, metrics, failure threshold, and CAPI scenarios are the client | Same middleware. Second `Open` changes one of `updateIntervalSeconds`, `metricsUpdateIntervalSeconds`, `updateMaxFailure`, or `crowdsecCapiScenarios`. Repeat once per field. | Different Client. Same `SessionHex`. |
| I2 | Live TTL is the client and the store | Second `Open` changes `defaultDecisionSeconds`. | Different Client. Different `SessionHex`. New store. |
| I3 | Startup block is neither key | Second config differs only by `streamStartupBlock`. | Same Client key. Same `SessionHex`. `Open` returns without waiting on the first poll. |

**Unsupported: two stream owners, same host and API key (WARN, do not fail New)**

| Id | Honour | Setup | Expect |
|---|---|---|---|
| C1 | Colliding stream owners | Two middlewares, distinct Traefik names, `crowdsecMode: stream`, `crowdsecLapiEnabled: true`, same `crowdsecLapiHost` and `crowdsecLapiKey`. | Both routes answer. `New` did not fail. `docker logs traefik-test` contains `crowdsec lapi stream collision` at WARN with both middleware names and the host. The API key is not in the line. |

**Config errors (Traefik `New` fails; route never serves)**

| Id | Honour | Setup | Expect |
|---|---|---|---|
| E2 | Bouncer off, leftover instance name | `enabled: false`, `crowdsecLapiEnabled: false`, and `crowdsecLapiInstanceName: shared`. | That router never comes up. Traefik error log. A known-good route in the same file still works. |
| E3 | Bouncer omits the instance name | `enabled: true`, `crowdsecLapiEnabled: false`, no `crowdsecLapiInstanceName`. AppSec off. | `New` succeeds. The LAPI name stays unset, so the bouncer does not subscribe and does not Open. No `crowdsec bouncer backend missing`. Requests call `next`. A known-good route in the same file still works. |
| E4 | `crowdsecMode: appsec` | Removed value. | `New` fails or the suite never ships that YAML; AppSec-only is T4. |

Do not add a test that waits in `New` for the named client. L1 is the proof that we did not.

---

## Assumed technical debt that must be created as part of the scope in knowledge/debt

This change must land the following files. Whether "ready" means more than "the subscribed client is published", and the knob's name, are still open. AppSec TLS not following LAPI is assumed OK for this change.

| File | What it records |
|---|---|
| `knowledge/debt/2026-09-22-stream-startup-block-rethink.md` | The knob's name still says stream startup. `true` now asks, on the request path, whether every backend this bouncer subscribes to is published. One subscription checks only that one. A published client counts as ready even while the first poll is in flight. What "ready" should mean past that, and the knob's name, are still open. Do not block `New`. |
| `knowledge/debt/2026-09-22-appsec-tls-follows-lapi.md` | An empty AppSec scheme is filled from LAPI, and the AppSec TLS material is not. Inherited `https` uses an empty AppSec CA. Assumed OK for this change. Later, copy LAPI CA, client certificate, and insecure-verify when no AppSec TLS material is set. |

---

## Constraints from the discussion

- Beta: we can change behaviour. We chose not to force dummy routers on simple setups.
- Traefik constructor order is unordered. Never wait in `New`. A subscriber that blocked until the owner `New` deadlocks when it is constructed first. Bind off the request path (Subscribe + Publish into `atomic.Value`). `ServeHTTP` only Loads `bouncer.lapi` and `bouncer.appsec`. `streamStartupBlock: true` asks, on the request path, whether every backend this bouncer subscribes to is published. One subscription checks only that backend. A missing subscribed client is 503. `false` uses that leg's failure action. The check does not block `New`. The knob's name, and whether ready means more than "published", stay open in `knowledge/debt/2026-09-22-stream-startup-block-rethink.md`.
- `enabled` stays the bounce switch. `false` calls `next` and still Opens. Knob renames are later.
- README must explain optional dummy vs bouncing subscribers vs one-middleware all-in-one.
- Ownership `Open` key is the middleware name plus every knob of that client. LAPI adds `updateIntervalSeconds`, `metricsUpdateIntervalSeconds`, `updateMaxFailure`, `crowdsecCapiScenarios`, and `defaultDecisionSeconds` to mode, scheme, host, path, key, TLS, effective HTTP timeout, Redis, `crowdsecLapiStreamScopes`, and CAPI credentials. `defaultDecisionSeconds` is also in `SessionHex`, because live TTLs are stored. The other four are not. `streamStartupBlock` is on the bouncer only. AppSec: scheme, host, path, resolved key, body limit, TLS, effective HTTP timeout. The instance name, `enabled`, `crowdsecAppsecFailureAction`, and `decisionScopeHeaders` are not in the client key. A different middleware name is a different Client. `AdoptTransport` does not apply an AppSec timeout or TLS change. The DecisionStore key stays `SessionHex`. In stream mode that hash includes the canonical scope list. It includes the whole Redis set only when `redisCacheEnabled` is true, and no Redis fields when it is false, so a Redis change builds a new store and a `startup=true` refill. Subscribers do not hold it; zero subscribers leaves it up. `ServeHTTP` reads `crowdsecMode` from the bound client. `crowdsecLapiStreamScopes` is explicit; an omitted list does not copy `decisionScopeHeaders`. When AppSec is enabled, `Prepare` copies an empty `crowdsecAppsecKey` from `crowdsecLapiKey` and an empty `crowdsecAppsecScheme` from `crowdsecLapiScheme` before the owner test, so a LAPI key then opens AppSec. `crowdsecAppsecHost` is not copied and stays `crowdsec:7422` unless set. Clear compares the dying Client to `slot.current`. Subscribers must not Bind reclaim.
- A slot is leg plus instance name. LAPI and AppSec do not share slot storage, so both may be named `shared`. A slot records the middleware that published it. Another middleware cannot unpublish that slot. There is no name check before `Open`. A publish-leg is opened on a child of the constructor context (`context.WithCancel`). Publish under the slot mutex is the rejection: a name already held by another middleware in that table does not change `current` or the recorded publisher. `New` then cancels that child, so the opened client Sleeps, and returns the error. One child covers every `Open` in that `New`. On success the child is not cancelled. If one leg of the same `New` is rejected, every slot that attempt already wrote is unpublished before the mutex is released. A subscribe-only leg is not published. The ERROR is `crowdsec instance name taken`. The rejected route does not answer. The name has to be released, and Traefik has to construct the rejected middleware again, before it can publish.
- Required proof is real-stack e2e (`tests/e2e/real`), including file-provider reload for A–D. Mock e2e does not count for reclaim overlap.

---

## Current (code)
- `plugin.go` — `New` validates, `lapi.Prepare` / `appsec.Prepare`, then `OpenStream` / `OpenLive` when mode is not `appsec`, else skips LAPI; opens AppSec when `CrowdsecAppsecEnabled`; always passes concrete `*lapi.Client` and `*appsec.Client` into `bouncer.New`. No subscribe/publish slot layer.
- `pkg/configuration/configuration.go` — `CrowdsecMode` includes `appsec` (`AppsecMode`). `Enabled` defaults via `New()`. No instance-name or LAPI-enabled fields. `StreamStartupBlock` exists (default true in `New()`).
- `pkg/bouncer/bouncer.go` — Holds direct `lapiClient` / `appsecClient` pointers; copies `crowdsecMode` and `decisionScopeHeaders` at `New`. `ServeHTTP` uses those fields; no `atomic.Value` late bind.
- `pkg/lapi/session.go` — `OpenStream` reclaims by `SessionKey` (session + Redis params); `rejectForeignStoreOwner` fails `New` when another Traefik name owns the same `SessionHex` store. Stream poll scopes union from registered `decisionScopeHeaders` (`pkg/lapi/zzz_scopeunion_test.go`), not a separate opener list.
- `pkg/lapi/client_stream.go` — `StreamStartupBlock` blocks inside client/stream startup path when true, not a bouncer-only "subscribed backends published" guard on `ServeHTTP`.
- `pkg/lapi/identity.go` — Live/none Open key uses `SessionHex` + identity payload; comments omit several knobs the spec wants on the ownership key.
- `pkg/appsec/session.go` — AppSec reclaim by listener identity; two middleware names with identical knobs can share one Client (`pkg/appsec/zzz_session_test.go` documents today's reclaim behavior).
- `tests/e2e/real/` — No `instance_severance.Tests.ps1`; reload-heavy A–D cases from the spec are not present.

## Out of scope
- Renaming all config keys to domain prefixes; old-key aliases
- New decision-remapping product behavior beyond existing knobs
- Traefik core changes; mandatory dummy routers
- Using slot name alone as Client reclaim key
- Full YAML knob rename follow-on from the spec's "later" note

## Unknowns
- Exact package layout for dual slot tables (LAPI vs AppSec) and Yaegi-safe subscriber lists
- README section structure after behavior change
- Whether existing `2026-09-21-bouncer-instance-severance` branch work should be merged or superseded (not in caller spec)

## Tensions
- Spec requires `rejectForeignStoreOwner`-style `New` failure on same `SessionHex` with different Traefik names to become allowed when sharing via named slots and `SessionHex` rules change — today `pkg/lapi/session.go` rejects that case.
- Spec moves `streamStartupBlock` to bouncer request-path "subscribed client published" semantics; today `pkg/lapi/client_stream.go` applies it at client open/stream startup.
- Spec requires middleware name in AppSec ownership key (two names → two Clients); today `pkg/appsec/zzz_session_test.go` expects reclaim across names for identical knobs.
- Spec lists debt files not yet on `origin/master` under `knowledge/debt/` (only unrelated debt notes exist in the worktree).
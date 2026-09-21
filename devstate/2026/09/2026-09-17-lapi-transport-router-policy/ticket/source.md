# Plan: separar en `pkg/lapi` lo que sobrevive de lo que se reconstruye

## Objetivo

Minimizar la pérdida del stream de CrowdSec cuando se reconfiguran los settings del
middleware. Un reload de routers con la misma configuración —el caso habitual— no debe
perder el stream nunca.

## Causa raíz

`lapi.Client` mezcla tres cosas con ciclos de vida distintos en un solo objeto:

1. **Estado del cursor** — `isCrowdsecStreamStartup`, `isCrowdsecStreamHealthy`,
   `updateFailure` (`pkg/lapi/client.go:71-73`). Es lo único que no se puede reconstruir
   sin coste: reconstruirlo fuerza `startup=true`, o sea resync completo.
2. **Recursos sustituibles** — `httpClient` y `cacheClient` (`pkg/lapi/client.go:64-65`).
   Reconstruirlos no pierde nada.
3. **Política per-router** — `lapiFailureAction`, `redisUnreachableBlock`,
   `defaultDecisionTimeout` (`pkg/lapi/client.go:57-58,61`). No es estado compartido en
   absoluto: solo lo lee el bouncer.

La clave del reclaim es `SessionPrefix` + hash de los 18 campos de `streamSettings`
(`pkg/lapi/session.go:71-90`, `SessionKey` en `session.go:148-151`). Como los tres grupos
viven en el mismo objeto y el objeto está keyed por ese hash, **cualquier** cambio de
settings crea encarnación nueva y paga un resync.

El dato que lo hace innecesario: el cursor de CrowdSec vive en el servidor, en la fila del
bouncer seleccionada por SHA-512 de la `lapiKey` más la IP de salida de Traefik. Ninguno de
los 18 campos lo afecta. Y el prefijo del caché es `SessionHex` —solo el grupo cursor
(`pkg/lapi/session.go:153-160`)— así que con Redis el contenido ya sobrevive hoy a un
cambio de settings y el resync no compra nada.

## Arquitectura objetivo (contexto, no todo entra en este PR)

| Pieza | Identidad | Ciclo de vida |
|---|---|---|
| `StreamPoller` | identidad del cursor | reclaim; no se reconstruye por settings |
| `LapiTransport` | conexión + TLS + timeout | puntero sustituible dentro del poller |
| `DecisionStore` | cursor + parámetros del almacén | reclaim; compartido por proceso |
| `MetricsReporter` | identidad del cursor | reclaim |
| `Bouncer` | config completa del middleware | se reconstruye en cada reload |

## Alcance de ESTE PR

Dos movimientos que son una sola historia: **dejar de tratar la política per-router y los
recursos sustituibles como estado del cursor**. Los dos sacan campos del hash de settings,
que es la superficie de resync.

### Parte 1 — La política per-router baja al `Bouncer`

`lapiFailureAction` y `redisUnreachableBlock` **solo los lee el bouncer**, vía accesores:

- `pkg/lapi/client.go:351-353` `LapiFailureAction()` → único consumidor `pkg/bouncer/bouncer.go:236`
- `pkg/lapi/client.go:356-358` `RedisUnreachableBlock()` → único consumidor `pkg/bouncer/bouncer.go:181`

`defaultDecisionTimeout` (`pkg/lapi/client.go:58`) se lee solo en rutas de modo live:
`pkg/lapi/client_live.go:26,31` y `pkg/lapi/client_decisions.go:148-162` (`liveCacheTTL`).
El bouncer ya invoca esa ruta con `LiveLookup`, que ya recibe los scopes como parámetro.

Trabajo:

1. Mover los tres a `Bouncer` (`pkg/bouncer/bouncer.go:29-44` y su `New`), leídos de
   `config` igual que los demás campos per-router. `lapiFailureAction` pasa por
   `configuration.EffectiveFailureAction`, como ya hace `appsecFailureAction`
   (`bouncer.go:60`).
2. `LiveLookup` recibe el TTL por parámetro; borrar `c.defaultDecisionTimeout`.
3. Borrar los accesores `LapiFailureAction()` y `RedisUnreachableBlock()` del `Client`.
4. Sacar los tres de `streamSettings` (`pkg/lapi/session.go:71-90`) y de `settingsFrom`
   (`session.go:107-126`). Revisar `pkg/lapi/identity.go` por si los replica.
5. Sacar también `LapiStreamStartupBlock` del hash: **no se guarda en el `Client`**, solo se lee
   en `pkg/lapi/client_stream.go:37` al construir. Después del nacimiento no significa nada,
   así que tenerlo en la key cuesta un resync a cambio de nada.

Consecuencia aceptada: dos routers sobre el mismo cursor con `bouncerLiveTtlSeconds`
distinto escriben al mismo caché, así que gana el último en el TTL. Es benigno (TTL de un
lookup cacheado) y es el precio de que el caché sea compartido.

Consecuencia deseada: dos routers pueden diferir legítimamente en failure action y en
fail-closed de Redis. Hoy el segundo se ignora en silencio.

### Parte 2 — `LapiTransport` sustituible en caliente

El `*http.Client` se construye en `pkg/lapi/client.go:159-167` desde el TLS config y
`HTTPTimeoutSeconds`. Rotar un certificado hoy obliga a encarnación nueva y resync **solo
porque el transporte está soldado al mismo objeto que el cursor**.

Trabajo:

1. Extraer el transporte a su propio tipo con el `*http.Client` y la autenticación (la
   clave o el token CAPI; hoy `pkg/lapi/client_http.go:71` automuta `c.crowdsecKey`, que es
   un campo de identidad — el token pertenece al transporte).
2. Guardarlo en el `Client` con **`atomic.Value`**, igual que `rangeMembership`
   (`pkg/lapi/client.go:66`). **No usar `atomic.Pointer[T]`**: es genérico y Yaegi v0.16 no
   admite una instanciación genérica de otro paquete como campo de struct.
3. `AdoptTransport(cfg)` después del `Open`: construye el nuevo, lo publica con `Store`, y
   cierra el idle del viejo con el `closeIdle` que ya existe (`client.go:220`).
4. Sacar del hash de settings las tres de TLS más `HTTPTimeoutSeconds`.

Consecuencia: dos routers vivos con TLS distinto sobre un cursor → gana el último `New`
(hoy se ignora el del joiner). Es el cambio que hace funcionar la rotación de certificados.
Se logea a INFO con los campos concretos.

### Parte 3 — Trazabilidad a INFO

Ya existen cuatro líneas INFO con `mode` y `host` (`pkg/lapi/client.go:20-23`, emitidas por
`logInfo` en `client.go:274-278`). Les falta identidad y motivo.

1. Añadir a `logInfo` la key de sesión y un `reason`.
2. Línea nueva al sustituir transporte, nombrando los campos que cambiaron.
3. Línea nueva cuando un joiner vivo trae settings distintos, con la lista de campos
   ignorados y cuáles se adoptaron.
4. **No** subir a INFO las líneas de `pkg/reclaim` (`reclaim_put`, `reclaim_reclaim`,
   `reclaim_dispose` en `table.go:198,445,478,649`). Son `Debug` en código sincronizado
   desde upstream; subirlas es más divergencia en el fork. La capa `lapi` es además la única
   que sabe el porqué.

## Pruebas esperadas

- Reload que solo cambia `lapiFailureAction`: mismo `*lapi.Client` reclamado, y
  `StreamFetches()` sin incremento de `startup=true`. Hoy crea uno nuevo.
- Reload que solo cambia un campo TLS: mismo `*lapi.Client`, transporte nuevo, continuidad
  del cursor.
- Dos routers con `lapiFailureAction` distinto sobre un cursor: cada bouncer aplica el suyo.
- `bouncerLiveTtlSeconds` per-router en modo live.
- Los helpers `waitStreamSessionInGrace` (`pkg/lapi/zzz_session_test.go:187-200`) y
  `waitPluginStreamInGrace` (`zzz_plugin_test.go:457-470`) siguen valiendo.

## Fuera de alcance de este PR

Dejar como follow-up en `knowledge/debt/`, no implementar:

- **`DecisionStore` compartido.** Hoy `localCache` ignora el prefijo y cada `Client` se
  queda su propio mapa (`pkg/cache/cache.go:183-184`), así que el lease `updated` de
  `client_stream.go:66-81` no se comparte con caché en memoria. Convertirlo en entrada de
  reclaim keyed por cursor+almacén (el `Close()` de `cache.Client` ya sirve de hook y ya es
  seguro llamarlo más de una vez, `cache.go:251`), y hacer el lease atómico con EVAL.
- **Estrechar la key al cursor.** Borrar `Peek`, `PeekLivePrefix` y `View`
  (`pkg/reclaim/peek.go`), pasar `scopes=` a unión de los routers vivos en vez de gana-el-
  primero, y convertir `pkg/reclaim` en un import real de traefik-middleware-utilities más
  un shim de tabla de proceso.
- Tocar `pkg/appsec`, el captcha o el AppSec.
- Mover el `MetricsReporter` a su propia pieza.

## Tensiones conocidas

- La spec viva `core_plugin_middleware_instance-reclaim` enumera qué entra en el hash de
  settings y fija warn-and-wire como gana-el-primero. Las partes 1 y 2 la contradicen a
  propósito. Que FindSpecHost decida en propose si se dobla ahí o si la política per-router
  merece hoja propia.
- Los campos de valor del `Client` son write-once y sus lectores no cogen el mutex
  (`handleStreamTicker` en `client_stream.go:48-63` lee `updateFailure`, `lapiUpdateMaxFailure`
  e `isCrowdsecStreamHealthy` sin lock, y `startTicker` lanza `go work()` en cada tick). Por
  eso este PR **no** hace mutables esos campos: los que se mueven salen del objeto y el
  transporte va por `atomic.Value`. No convertir escalares a mutables aquí.

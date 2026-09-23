# Standards

1. [hard] Leave a trail — `README.md:136` — architecture table still names the bounce flag `enabled` after `Enabled` became `BouncerEnabled`
   Fix: Write `bouncerEnabled` in the table and the following sentence (`enabled never opens` / `enabled: true`)
   Status: done
   Argument: README architecture table and following sentence now say `bouncerEnabled`.
   Quote:
      ```
      | Bouncer | `enabled` | Serve this router: subscribe to those names, apply this route’s remediations (status, header, captcha, trusted IPs, failure action). |

      `enabled` never opens a backend. ... A bouncing subscriber sets `enabled: true` and the instance name
      ```
2. [hard] Leave a trail — `README.md:124` — modes prose still names `MetricsUpdateIntervalSeconds` after the knob became `LapiMetricsUpdateIntervalSeconds`
   Fix: Name `lapiMetricsUpdateIntervalSeconds` on that sentence
   Status: done
   Argument: README modes sentence now names `lapiMetricsUpdateIntervalSeconds`.
   Quote:
      ```
      Usage-metrics still POST to LAPI on `MetricsUpdateIntervalSeconds` unless that interval is zero or less.
      ```
3. [hard] Leave a trail — `README.md:314` — Variables catalog still heads the ban template as `BanFilePath` after the field became `BouncerBanFilePath`
   Fix: Head the entry `BouncerBanFilePath` (YAML `bouncerBanFilePath`)
   Status: done
   Argument: README Variables catalog now heads `BouncerBanFilePath`.
   Quote:
      ```
      **BanFilePath** (string, default `""`)
      Path to the ban file. Empty disables it. Content-Type is inferred from the extension.
      ```
4. [hard] Leave a trail — `pkg/lapi/client.go:125` — edited error still uses event prefix `New:crowdsecLapiKey` after the field is `LapiKey`
   Fix: Prefix the log `New:lapiKey` (match the message and the returned `LapiKey is missing`)
   Status: done
   Argument: `pkg/lapi/client.go` error prefix is now `New:lapiKey`.
   Quote:
      ```
      log.Error("New:crowdsecLapiKey fail to get LapiKey and no client certificate setup")
      ```
5. [hard] Leave a trail — `pkg/appsec/client.go:61` — edited info still uses event prefix `Prepare:crowdsecAppsecKey` after the field is `AppsecKey`
   Fix: Prefix the log `Prepare:appsecKey`
   Status: done
   Argument: `pkg/appsec/client.go` info prefix is now `Prepare:appsecKey`.
   Quote:
      ```
      log.Info("Prepare:crowdsecAppsecKey fail to get AppsecKey and no client certificate setup", "error", errAppsecKey)
      ```
6. [hard] Leave a trail — `pkg/configuration/configuration.go:547` — comment now says `BouncerEnabled` AppSec; `rejectMissingEnabledAppsecHost` gates on `AppsecEnabled`
   Fix: Say owned/enabled AppSec (`AppsecEnabled`), not the bounce flag
   Status: done
   Argument: Comment on `rejectMissingEnabledAppsecHost` now says `AppsecEnabled`.
   Quote:
      ```
      // BouncerEnabled AppSec needs a listener host. validateURL only asks NewRequest to
      ```
7. [hard] Symmetry and consistency — `pkg/lapi/identity.go:27` — this change dropped Redis JSON to `enabled`/`host` on `storeParams` and left `identity`/`ownership` on `redisCache*`
   Fix: Use the same Redis JSON names on `identity` and `ownership` as `storeParams` (`enabled`, `host`, `readHosts`, `password`, `database`)
   Status: done
   Argument: Nested `storeParams` as `json:"redis"` on `identity` and `ownership` so Redis uses those names without colliding with LAPI `host`/`key`.
   Quote:
      ```
      RedisEnabled                 bool     `json:"redisCacheEnabled"`
      RedisHost                    string   `json:"redisCacheHost"`
      ```

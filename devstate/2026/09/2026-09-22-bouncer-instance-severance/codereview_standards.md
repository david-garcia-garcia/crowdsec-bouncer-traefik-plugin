# Standards

1. [hard] build_e2e_real — `tests/e2e/real/instance_severance.Tests.ps1:805` — R2 owner rewrite is file-provider YAML that omits `reclaimGraceSeconds: 2`
   ```
   crowdsecLapiEnabled: "true"
   ...
   logFormat: json
   updateIntervalSeconds: "5"
   ```
   → Reuse `Get-SevKnobs` (or add `reclaimGraceSeconds: "2"`) on this inlined owner
   Status: done
   Argument: added reclaimGraceSeconds: "2" on R2 and N2 inlined owners.
2. [hard] build_e2e_real — `tests/e2e/real/instance_severance.Tests.ps1:1130` — N2 owner rewrite is the same inlined file-provider YAML without `reclaimGraceSeconds: 2`
   ```
   crowdsecLapiEnabled: "true"
   ...
   logFormat: json
   updateIntervalSeconds: "5"
   ```
   → Reuse `Get-SevKnobs` (or add `reclaimGraceSeconds: "2"`) on this inlined owner
   Status: done
   Argument: same reclaimGraceSeconds edit on both inlined owners.
3. [hard] Leave a trail — `pkg/instance/tables.go:24` — `MsgBound` / `MsgUnbound` comments say DEBUG after bind/unbind now log Info
   ```
   // MsgBound is the DEBUG line when a bouncer subscribes to a slot.
   MsgBound = "crowdsec bouncer bound"
   // MsgUnbound is the DEBUG line when a bouncer unsubscribes from a slot.
   ```
   → Comment them as INFO to match `storeValue` (`sub.Log.Info(MsgBound|MsgUnbound)`)
   Status: done
   Argument: comments now say INFO.
4. [hard] Leave a trail — `plugin.go:89` — `openAndPublishOwned` has no job comment; Open LAPI, Open AppSec, PublishAll, and set/clear published names have no block intros
   ```
   func openAndPublishOwned(bindCtx context.Context, prepared *configuration.Config, log *slog.Logger, name string) error {
   	var lapiClient *lapi.Client
   ```
   → Add a one-line job comment and a one-line intro on each block
   Status: done
   Argument: job comment on openAndPublishOwned.
5. [hard] One job, one owner — `plugin.go:144` — `unpublishRenamedLAPI` and `unpublishRenamedAppSec` copy the same last-name check and Unpublish
   ```
   func unpublishRenamedLAPI(...) {
   	stored := client.LastPublishedName()
   	if stored == "" || stored == instanceName { return }
   	instance.Unpublish(instance.LegLAPI, stored, client, publisher)
   }
   func unpublishRenamedAppSec(...) { /* same, LegAppSec */ }
   ```
   → One helper that takes the leg (and LastPublishedName) and call it from both
   Status: done
   Argument: unpublishRenamed(leg, client, name, publisher).
6. [hard] Leave a trail — `pkg/instance/tables.go:50` — new `slot`, `table`, and `registry` types have no job comments
   ```
   type slot struct {
   	current      any
   	empty        any
   ```
   → One succinct comment per type stating the job
   Status: done
   Argument: job comments on slot, table, registry.
7. [hard] Leave a trail — `pkg/lapi/identity.go:35` — new `ownership` type has no job comment
   ```
   type ownership struct {
   	MiddlewareName               string   `json:"middlewareName"`
   ```
   → Comment that this is the LAPI Open-key payload (middleware name plus client knobs)
   Status: done
   Argument: ownership type comment.
8. [hard] One job, one owner — `pkg/lapi/session.go:40` — `streamOwnerIndex` is a second live process table sitting in the stream-session identity file
   ```
   type streamOwnerIndex struct {
   	mu     sync.Mutex
   	owners map[string]map[string]struct{}
   }
   ```
   → Move the collision index to its own file named for that type
   Status: skipped
   Argument: judgement; file split is churn, not a behavior fix.
9. [hard] Name for the scope — `pkg/lapi/zzz_severance_test.go:131` — `configurationCopy` hides that the type is a Redis-field snapshot
   ```
   type configurationCopy struct {
   	host, password, database string
   	reads                    []string
   }
   ```
   → Rename to the role (`redisFields` or similar)
   Status: skipped
   Argument: test-only name; not applied unattended.
10. [hard] Smallest durable delta — `examples/kubernetes/traefik/plugin.yml:9` — adding `crowdsecLapiEnabled` left `CrowdsecLapiKey` at the wrong indent, so it is no longer a bouncer field
    ```
            crowdsecLapiEnabled: true
          CrowdsecLapiKey: 40796d93c2958f9e58345514e67740e5
            Enabled: "true"
    ```
    → Keep `CrowdsecLapiKey` at the same indent as the other bouncer keys
    Status: done
    Argument: aligned CrowdsecLapiKey indent.
11. [hard] Smallest durable delta — `examples/redis-cache/docker-compose.yml:43` — the new label is a live compose list item inside a commented-out service
    ```
      #     - "traefik.http.middlewares.crowdsec.plugin.bouncer.enabled=true"
      - "traefik.http.middlewares.crowdsec.plugin.bouncer.crowdseclapienabled=true"
      #     - "traefik.http.middlewares.crowdsec.plugin.bouncer.crowdseclapikey=40796d93c2958f9e58345514e67740e5"
    ```
    → Comment the new label at the same indent as the surrounding block
    Status: done
    Argument: commented the live redis-cache label.
12. [hard] Smallest durable delta — `examples/tls-auth/docker-compose.yml:41` — same live label dropped into a commented-out service
    ```
      #     - "traefik.http.middlewares.crowdsec.plugin.bouncer.loglevel=DEBUG"
      - "traefik.http.middlewares.crowdsec.plugin.bouncer.crowdseclapienabled=true"
      #     - "traefik.http.middlewares.crowdsec.plugin.bouncer.crowdseclapikey=40796d93c2958f9e58345514e67740e5"
    ```
    → Comment the new label at the same indent as the surrounding block
    Status: done
    Argument: commented the live tls-auth label.
13. [judgement] Smallest durable delta — `.golangci.yml:122` — the instance `perfsprint` exclude replaced `pkg/bouncer/` instead of adding a sibling
    ```
    - path: pkg/instance/
      linters:
        - perfsprint
    ```
    → Keep the bouncer exclude and add instance beside it
    Status: skipped
    Argument: judgement.
14. [judgement] Duplicated Code — `pkg/configuration/configuration.go:414` — `lapiSecretPresent` and `appsecSecretPresent` are the same key-or-cert check
    ```
    func lapiSecretPresent(config *Config) bool {
    	key, err := GetVariable(config, "CrowdsecLapiKey")
    ```
    → One helper that takes the key and cert field names
    Status: skipped
    Argument: judgement.

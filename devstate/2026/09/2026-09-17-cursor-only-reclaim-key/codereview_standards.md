# Standards

1. [hard] Name for the scope — `pkg/lapi/liveheaderscopes.go:8` — `holders` is reclaim’s nickname for a bound constructor ctx, not the role this field has (ctx → header-scope map)
   → Rename to `headerScopesByCtx`
   Status: done
   Argument: renamed field to headerScopesByCtx
   ```
   type liveHeaderScopes struct {
   	holders map[context.Context]map[string]string
   }
   ```
2. [hard] Name for the scope — `pkg/lapi/zzz_session_test.go:283` — `aCfg` / `a` and `bCfg` / `b` are letter placeholders for the Redis-A vs Redis-B Client pair
   → Rename to `redisACfg` / `redisAClient` and `redisBCfg` / `redisBClient`
   Status: done
   Argument: renamed to redisACfg / redisAClient and redisBCfg / redisBClient
   ```
   aCfg := testStreamConfig(parsed.Host, 1)
   aCfg.LapiRedisHost = "redis-a:6379"
   ...
   a, err := OpenStream(ctx, aCfg, log, "a", "test")
   ```
3. [hard] Name for the scope — `pkg/lapi/zzz_session_test.go:318` — same `a` / `b` placeholders for the Country vs username pair the sibling test already names `countryCfg` / `userCfg`
   → Rename to `countryCfg` / `countryClient` and `userCfg` / `userClient`
   Status: done
   Argument: renamed to countryCfg / countryClient and userCfg / userClient
   ```
   aCfg.LapiScopeHeaders = map[string]string{"Country": "CF-IPCountry"}
   bCfg.LapiScopeHeaders = map[string]string{"username": "X-User"}
   a, err := OpenStream(ctx, aCfg, log, "a", "test")
   ```
4. [hard] Leave a trail — `pkg/lapi/zzz_session_test.go:429` — helper now waits on `Client.sleeping` but the failure string still says the session did not enter grace
   → Change the fatal to say the Client never Sleep’d
   Status: done
   Argument: fatal now says Client never Sleep'd
   ```
   // waitClientSleeping fails if the Client never Sleeps after its last holder is gone.
   ...
   	t.Fatal("stream session did not enter grace")
   ```

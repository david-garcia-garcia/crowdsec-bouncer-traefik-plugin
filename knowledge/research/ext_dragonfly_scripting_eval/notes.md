# Dragonfly EVAL / EVALSHA

Whether Dragonfly accepts Redis Lua `EVAL` and `EVALSHA` so this plugin’s stream lease can use vendored SimpleRedis `Eval` against the real-stack cache (Dragonfly, not Redis).

Fetched: 2026-09-17. Compatibility table verified against Dragonfly v2.0.0 / Redis 8.6.4.

## Scripting commands this lease needs

Official compatibility table (command surface only; “Fully supported” does not mean byte-for-byte identical behaviour):

| Command | Table |
| --- | --- |
| EVAL | Fully supported |
| EVALSHA | Fully supported |
| EVAL_RO | Fully supported |
| EVALSHA_RO | Fully supported |
| SCRIPT LOAD | Fully supported |
| SCRIPT EXISTS | Fully supported |
| SCRIPT FLUSH | Partially supported — missing ASYNC, SYNC |
| SCRIPT DEBUG | Unsupported |
| SCRIPT KILL | Unsupported |
| FUNCTION * / FCALL | Unsupported |

Owner: [API Compatibility](https://www.dragonflydb.io/docs/command-reference/compatibility). Extract: `.sources/compatibility.md`.

Vendored SimpleRedis `Eval` sends `EVALSHA` of the caller digest, then one `EVAL` of the body on `NOSCRIPT`. That pair is on the fully-supported rows. It does not need `FUNCTION` / `FCALL` or `SCRIPT DEBUG` / `KILL`.

Owner of the client hop: `this-repo` vendor `github.com/david-garcia-garcia/traefik-middleware-utilities/simpleredis/commands_eval.go` (`Eval`, `ScriptSHA1Hex`). Product usage of that client: `knowledge/devdocs/core_cache_redis.md`.

`SET NX` is a different command (also fully supported). This finding is the Lua path the ticket names, not SET NX.

## e2e

Real-stack cache e2e already uses Dragonfly (`knowledge/devdocs/core_cache_redis.md`). Pin and image stay on `ext_dragonfly_redis-protocol/`. An `EVAL`/`EVALSHA` lease against that stand-in is on the documented scripting surface.

## References

- Official: [Dragonfly API Compatibility](https://www.dragonflydb.io/docs/command-reference/compatibility)
- Extract: `.sources/compatibility.md`

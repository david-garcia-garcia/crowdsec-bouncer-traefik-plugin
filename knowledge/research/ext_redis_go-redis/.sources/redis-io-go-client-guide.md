---
url: https://redis.io/docs/latest/develop/clients/go/
title: go-redis guide (Go)
fetched: 2026-09-05
authority: official
---

Redis' own client documentation for Go.

## Claims used

- "`go-redis` is the Go client for Redis." It is the only Go client this page documents.
- Install: `go get github.com/redis/go-redis/v9`.
- "`go-redis` supports the last two Go versions. You can only use it from within a Go module."
- Canonical construction:

```go
rdb := redis.NewClient(&redis.Options{
    Addr:     "localhost:6379",
    Password: "",
    DB:       0,
    Protocol: 2,
})
ctx := context.Background()
```

- Connection-string form: `redis.ParseURL("redis://<user>:<pass>@localhost:6379/<db>")`, then `redis.NewClient(opt)`.
- Command idiom is `(ctx, ...)` then `.Err()` / `.Result()`:

```go
err := rdb.Set(ctx, "foo", "bar", 0).Err()
val, err := rdb.Get(ctx, "foo").Result()
```

- Teardown is `rdb.Close()`.

## redigo

The page's cross-language client legend enumerates one client per language:

> Go: go-redis client

`github.com/gomodule/redigo` does not appear anywhere on this page. Redis' current official
Go documentation names only `go-redis`, so no redigo fallback is carried into `notes.md`.

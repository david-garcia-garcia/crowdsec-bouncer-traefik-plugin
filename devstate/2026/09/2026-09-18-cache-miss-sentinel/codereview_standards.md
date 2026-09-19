# Standards

1. [hard] Leave a trail — `pkg/cache/zzz_cache_test.go:342` — new `sentinelFor` has no succinct job comment
   → Add one line that it maps table `valueErr` text (`CacheMiss` / `CacheUnreachable`) to `ErrMiss` / `ErrUnreachable` for `errors.Is`
   Status: done
   Argument: job comment on sentinelFor in pkg/cache/zzz_cache_test.go

```
func sentinelFor(text string) error {
	switch text {
	case CacheMiss:
		return ErrMiss
	case CacheUnreachable:
		return ErrUnreachable
	default:
		return errors.New(text)
	}
}
```

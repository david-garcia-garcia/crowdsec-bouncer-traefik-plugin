# Standards

1. [hard] Symmetry and consistency — `pkg/reclaim/zzz_alias_test.go:25` — `watchInto` still assigns `boxed.Value` in place while `storeBinding` now always `Store`s a new `*reclaim.Box`; same publish role, divergent shapes
   Fix: In `watchInto`, `Store` a new `*reclaim.Box` on every update (same shape as `storeBinding`)
   Status: skipped
   Argument: human left deviation proposed/Requester not asked; watchInto reshape not applied unattended.
   Quote:
      ```
      if boxed, ok := dest.Load().(*Box); ok {
      	boxed.Value = notice.Value
      	return
      }
      ```

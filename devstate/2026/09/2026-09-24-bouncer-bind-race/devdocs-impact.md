# Devdocs impact
change: bouncer-bind-immutable-box
fixedPoint: origin/master
head: f4d7d3836d766205b457ddad26abb649f9df3b51

## Units
- Instance slots — subsystem — `knowledge/devdocs/core_plugin_middleware_instance-slots.md` (Watcher `Store` / Publish into subscriber `atomic.Value`; `storeBinding` late-bind path)
- Reclaim context lease — pattern — `knowledge/devdocs/std_go_reclaim.md` (`*Box` Watcher binding; Yaegi type-freeze)
- Bouncer late bind — subsystem — `openspec/.../core_plugin_middleware_bouncer` (catalog owner); usage stays on instance-slots + reclaim packets (no dedicated bouncer usage leaf)

## Findings
none.

Verified: apply already lands Gotchas on `core_plugin_middleware_instance-slots` (How-to + Gotchas) and `std_go_reclaim` (Gotchas) for Store-new-`*Box` / no in-place `Box.Value`. Matches `storeBinding`. No Language gap (Publish / Watcher / Bouncer terms already define the subsystem). No new leaf. `watchInto` left unbuilt — not documented as fixed. Findings 2 and 3 out of scope.

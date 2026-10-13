# reclaim alias and Peek at utilities v1.0.7

Tag `v1.0.7` is commit `42e6a1a967155318023c4defe491d1d423e165b6` (message: add alias SetAlias/Watch, Peek, and unbind on teardown). Tag `v1.0.6` has no `reclaim/alias.go`.

## Published surface

`reclaim/alias.go` exports `Watcher`, `Box`, `Published`, and `(*Table).SetAlias(key, alias, publisher, group)`, `Watch(ctx, alias, empty, changed)`, `ClearPublisher(publisher, group)`. Holders stay on the ownership key. Watchers are weak and receive `Published`. A second publisher on the same alias is rejected. Same publisher may rename in the same group. Watch never waits and never binds a holder. ClearPublisher drops that publisher's aliases in the group; watchers stay.

`reclaim/table.go` at that commit has `aliases map[string]*aliasEntry` on `Table`, `aliases []*aliasEntry` on `slot`, `unbindIncarnationLocked` on incarnation end (including expire and Reset `takeAll`), plus exported `State` (`Awake`, `Asleep`) and `(*Table).Peek(key) (any, State, bool)`. Peek does not wait, bind, Wake, or stop grace. Busy/gone/missing → `ok=false`.

`Open`, `OpenWithHooks`, `Reset`, `Hooks`, `Config`, `New` stay. `OpenTyped` is still a separate file.

## Relation to this plugin's dest vendor

Dest vendors v1.0.6 plus a local `alias.go` and table edits. Dest `alias.go` methods and types match published v1.0.7; the package comment still says "Ad-hoc vendor override". Dest `table.go` git-blob `8190037ce6c180b169dbdc8d25cf35197ae16a05` differs from published v1.0.6 (`5fde20a7a2871358d7eb7efa85f2814cc29aa3f6`) and from published v1.0.7 (`dcc3d85afa8dd59df2f0d8a21620a18f7ab8173c`). Published Peek adds `//nolint:exhaustive` on the state switch. A clean re-vendor takes the published files; do not re-apply the dest vendor diff.

## Unchanged sibling packages at this tag

`simpleredis/*.go` and `iplookup/{helper,tree}.go` blobs at v1.0.7 equal v1.0.6 and equal dest `vendor/` copies of those paths. Re-vendoring v1.0.7 does not drop a dest simpleredis or iplookup patch.

Sources: `.sources/alias-go.md`, `.sources/table-go.md`, `.sources/v1-0-7-tag.md`.

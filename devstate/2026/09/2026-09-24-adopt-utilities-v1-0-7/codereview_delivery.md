# Delivery

## Motivation

The tree already pins `traefik-middleware-utilities` for reclaim, SimpleRedis, and iplookup. Dest still requires `v1.0.6`. Two APIs the tree already uses are not in that pin: the generation-Apply test helper lives under `pkg/traefikemulator`, and reclaim `SetAlias` / `Watch` / `ClearPublisher` / `Peek` live as a hand-patched vendor tree.

Published `v1.0.7` already ships both. Dest therefore keeps a second owner of the emulator file and an ad-hoc Peek that published `v1.0.6` does not have. Main Process CI comments `go mod vendor` out so a restore of that published tree does not drop Peek and fail typecheck. Live specs still name `v1.0.6` and say Peek is ad-hoc on vendored `table.go`.

If those copies stay, a later vendor restore or a catalog load that does not use this `vendor/` drops Peek, and exclusive-name detection cannot compile. The emulator remains a second owner of a file that already exists at the published tag. Catalog and usage sentences still promise a pin and a vendor override that are no longer the source of those APIs.

Priority: P3 — pin, local copies, and CI vendor skip, no current operator or user harm

## Implementation

Require `traefik-middleware-utilities v1.0.7` and re-vendor so `vendor/` matches the published module: reclaim (alias and Peek) and `traefikemulator`. Do not re-apply the dest reclaim vendor diff. Delete `pkg/traefikemulator` and point the remaining caller at the published import. Swap the Test depguard allowlist and the helper doc to that path. Keep `pkg/reclaim` as the only product import of utilities reclaim.

Re-enable `go mod vendor` and the vendor git-diff on Main Process. Before Yaegi, copy the vendored utilities tree onto `$GOPATH/src` so the test-only `traefikemulator` import resolves (Yaegi v0.16 does not load it from `vendor/`). Fold the live spec pin `v1.0.6` to `v1.0.7` and the Peek-owner sentence onto the published table method.

## What this changes
**Operators.** None.
**Admin users.** None.
**Developers.** Tests import `github.com/david-garcia-garcia/traefik-middleware-utilities/traefikemulator` (the local package is gone); `go.mod` pins utilities `v1.0.7` with published reclaim Peek and alias; callers still use the `pkg/reclaim` shim; Yaegi root-package tests need that module on `$GOPATH/src`.
**End users.** None.

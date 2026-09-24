# 2026-09-24-adopt-utilities-v1-0-7

issueHost: local
issueRef: none

## Spec

Depend on github.com/david-garcia-garcia/traefik-middleware-utilities v1.0.7 (tag v1.0.7, commit 42e6a1a967155318023c4defe491d1d423e165b6 on master) and remove the ad-hoc local copies that this release now contains.

What landed upstream in v1.0.7:
- New package traefikemulator (was pkg/traefikemulator in this plugin).
- reclaim alias support: reclaim/alias.go plus table.go changes (SetAlias/Watch, Peek, unbind on teardown). The plugin currently vendors v1.0.6 plus those local edits under vendor/github.com/david-garcia-garcia/traefik-middleware-utilities/reclaim.

Desired:
- go.mod / go.sum require v1.0.7. Re-vendor so vendor matches that module. Do not keep a hand-patched vendor tree for packages v1.0.7 already publishes.
- Delete pkg/traefikemulator. Callers (including zzz_traefikemulator_test.go and any other import of github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/traefikemulator) import github.com/david-garcia-garcia/traefik-middleware-utilities/traefikemulator instead.
- Plugin code that uses reclaim keeps using the module; it must compile against the v1.0.7 API. Do not re-apply the old vendor diff.
- Tests that used the local emulator keep passing against the upstream package.

Out of scope: tagging or releasing the bouncer itself; changing upstream further; unrelated simpleredis work unless re-vendoring v1.0.7 removes a local patch that the plugin still needs (if that happens, record it as an unknown, do not invent a new feature).

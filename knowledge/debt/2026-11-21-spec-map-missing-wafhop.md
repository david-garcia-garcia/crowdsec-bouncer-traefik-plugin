# Add the `wafhop` component to `openspec/specs/map.md`

IssueKey: 2026-11-21-lapi-ban-retry-after
Size: small
Action: note

## Why this follow-up
`validate-spec-map` fails on `master`: `map.md` has no `wafhop` component under `### plugin` (`## core`), although `openspec/specs/core_plugin_wafhop_shared-request/` exists since #190. The archive move expects a clean map.

## Why it was not taken
This change adds no spec folder and does not touch `map.md`. Unattended implement takes only rows on artifacts this run created.

## Risks
Archive of any change stops on the map check until the line is added (`validate-spec-map --write` regenerates it).

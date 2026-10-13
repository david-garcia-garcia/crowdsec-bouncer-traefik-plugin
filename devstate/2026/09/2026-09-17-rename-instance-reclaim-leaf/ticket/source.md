This ticket takes the follow-up recorded in `knowledge/debt/2026-09-17-rename-core-plugin-middleware-instance-reclaim.md`. Read that file as the ticket source.

The live spec leaf `openspec/specs/core_plugin_middleware_instance-reclaim/spec.md` has become a dumping ground. It now describes at least four distinct units: the session prefix (LAPI URL plus bouncer key), the first-wins settings hash that keys reclaim, last-`New`-wins transport adoption, and per-router Bouncer policy (failure action, Redis fail-closed, live-cache TTL). The leaf name `instance-reclaim` names none of them, so every later change folds into it and it keeps growing.

The human has explicitly approved this rename, which satisfies the approval requirement in `skill:sbs-dev-workflow:Issues` ("Do not rename or refactor an existing spec... without approval"). Decide, following `skill:sbs-dev-speclibrarian:Naming` and FindSpecHost, whether the right move is one rename to a precise legal 4th part or a split into more than one leaf, and then do it. Both are acceptable outcomes; pick the one the naming grammar supports and record the reasoning. Do not fold onto another vague name.

Update every dependent reference you find: sibling live specs under `openspec/specs/`, `knowledge/devdocs/` packets (notably `core_plugin_middleware.md`, `core_plugin_lapi_connection.md`, `index_core_plugin.md`), and any `devstate/**/specs.md` pointer in the current run only. Per the skill, archived change folders under `openspec/changes/archive/` KEEP their historical spec ids — do not rewrite history there.

Scope fence — two sibling tickets are running in parallel:
This is a specs-and-docs ticket. Do NOT change product Go code: no edits under `pkg/`. The behaviour described must stay exactly what `master` (currently `e6cc9ab`, which just merged PR #62) already implements; if you find the spec text disagrees with the code, note it as a follow-up rather than changing either.

Do NOT touch, in this ticket:
- `openspec/specs/core_plugin_lapi_usage-metrics/` — a sibling ticket owns that leaf
- `openspec/specs/core_plugin_appsec_*` and `core_plugin_middleware_captcha-gate` — a sibling ticket owns those
- any file under `pkg/`

If a rename genuinely forces an edit inside a fenced-off leaf, stop and report it as `blocked` with the reason. Run `skill:sbs-dev-workflow:Sync` before implement and before pullrequest, because `master` may move under you when a sibling PR merges; merge `origin/master` and re-verify rather than rebasing a pushed branch.

When implement lands the work, close the debt per `skill:sbs-dev-workflow:Issues`: delete `knowledge/debt/2026-09-17-rename-core-plugin-middleware-instance-reclaim.md` and record the closure on your own run's `issues.md` and delivery card. Do NOT edit or stage the previous run's bus folder `devstate/2026/09/2026-09-17-lapi-transport-router-policy/`.

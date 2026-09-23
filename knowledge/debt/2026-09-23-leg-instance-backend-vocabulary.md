# Legs, instance, and backend are mixed

IssueKey: 2026-09-22-bouncer-instance-severance
Size: large
Action: note

## Why this follow-up

The same LAPI or AppSec client is named three ways. `leg` is the kind (`lapi` / `appsec`) in logs, alias groups, and `plugin.go` constants. `instance` / `instanceName` is the public publish name (`crowdsecLapiInstanceName`, `instanceAlias`). `backend` is what the bouncer says when a subscribed client is missing (`msgBackendMissing`, `streamStartupBlock` "subscribed backend"). Readers cannot tell whether a sentence is about the ownership key, the public alias, or the `atomic.Value` late-bind.

## Why it was not taken

The unification kept current HTTP/e2e behavior. Renaming YAML keys, log attrs, and usage-doc Language is a vocabulary pass, not this apply.

## Risks

New code and reviews keep inventing a fourth word. Operators and agents treat `instanceName` as the reclaim ownership key, or treat `backend` as a second table.

## Context

Owner: plugin constructor + instance-slots usage (`plugin.go`, `pkg/bouncer`, `knowledge/devdocs/core_plugin_middleware_instance-slots.md`).

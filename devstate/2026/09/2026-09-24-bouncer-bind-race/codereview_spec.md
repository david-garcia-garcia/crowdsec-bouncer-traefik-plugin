# Spec

1. [missing] Companion watchInto publish shape — `openspec/changes/bouncer-bind-immutable-box/tasks.md` — design Goals and proposal What Changes ask `watchInto` to Store a new `*reclaim.Box` each update; task 2.1 is unchecked and the helper still mutates in place
   Fix: Build task 2.1, or drop the companion from design/proposal/tasks and keep deviations.md as proposed-only
   Status: skipped
   Argument: human left deviation proposed/Requester not asked; watchInto reshape not applied unattended.
2. [judgement] Usage Gotcha rewrite in apply — `knowledge/devdocs/core_plugin_middleware_instance-slots.md` — design Non-Goals deferred usage rewrites to devdocsimpact; tasks 4.1 allow rewrite only on drift; apply still lands Gotcha lines that name the immutable-publish rule
   Fix: Leave as landed drift clarification, or move the doc edit to the dedicated impact phase
   Status: skipped
   Argument: judgement; landed as drift clarification of the immutable-publish rule; not reversed unattended.

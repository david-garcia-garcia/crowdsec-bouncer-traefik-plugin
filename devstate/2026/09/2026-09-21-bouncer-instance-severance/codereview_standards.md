# Standards

1. [judgement] Leave a trail — `plugin.go:20` — constructor comments explaining bindCtx rollback and config snapshot aliasing were removed without replacing block intros on the new Open/subscribe branches
   → Restore one-line intros on bindCtx defer and the OpensLAPI/OpensAppsec branches if the next edit touches this file
   Status: skipped
   Argument: comment-only; not applied unattended per minimal diff.

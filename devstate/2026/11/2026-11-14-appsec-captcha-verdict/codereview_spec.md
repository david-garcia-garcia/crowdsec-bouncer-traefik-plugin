# Spec

1. [judgement] Marker POST trigger wider than "AppSec ran" — `pkg/bouncer/bouncer.go:307` — the requirement "Challenge-marker POST let through by AppSec stays on the captcha gate" binds only "When AppSec ran on a request ... and did not write a response" and says every other request SHALL reach `next` as before; `serveAppSec` checks the marker whenever `applyAppsecServeHTTP` returned false, which also covers a subscribed but unpublished AppSec client with `bouncerAppsecFailureAction: passthrough` (no Query ran), so that marker POST goes to the captcha gate instead of `next`. Design decision 4 ("when `applyAppsecServeHTTP` did not write") matches the code, so the gap is the spec wording.
   Fix: Align the requirement wording with design decision 4 (AppSec leg, including a passthrough failure action, did not write), or gate the marker check on an AppSec Query having run
   Status: done
   Argument: Requirement reworded to "the AppSec leg (a verdict, or failure action `passthrough`) did not write", matching design decision 4.

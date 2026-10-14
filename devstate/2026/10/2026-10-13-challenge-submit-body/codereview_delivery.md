# Delivery

## Motivation
Bot-detection posts the visitor proof to `/crowdsec-internal/challenge/submit`. AppSec must receive that form in full. This fork already forwards the whole readable body when `appsecBodyLimit` is `0`, and the default 10MB cap is meant to be enough.

The README AppSec / bot-detection paragraph and the **AppsecBodyLimit** key never said the challenge proof depends on that body. An operator who set a smaller positive limit, or who read upstream PR 403 and thought `0` sends no body, had no fork-accurate warning.

Left alone, a truncated proof keeps the visitor on the challenge. The gap is operator wording, not the copy path.

Priority: P3 — docs and operator clarity; no current runtime change

## Implementation
Two README seams now state the same facts: `/crowdsec-internal/challenge/submit` must reach AppSec with the full form; the default 10MB is enough; a smaller positive limit cuts the proof short; `0` means no limit and the whole body is sent. Runtime and `Test_appsecQuery_zeroBodyLimitForwardsPost` are unchanged. `skip_specs` — no live-contract delta.

## What this changes
**Operators.** README now says the challenge submit POST needs the full form, the default 10MB is enough, a smaller positive limit cuts the proof short, and `appsecBodyLimit` `0` sends the whole body.
**Admin users.** None.
**Developers.** None.
**End users.** None.

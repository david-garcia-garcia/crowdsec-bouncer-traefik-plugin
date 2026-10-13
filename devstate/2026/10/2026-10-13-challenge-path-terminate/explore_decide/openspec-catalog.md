# Decision pass — Should dest grow an OpenSpec catalog so the ticket can “update the spec”?

IssueKey: 2026-10-13-challenge-path-terminate
Pass: 1
Rank before: structural incidental — would add openspec/ from scratch; Desired names a spec update, dest has no catalog
Rank after: additive incidental — dest has no existing spec catalog or callers to reshape; bootstrapping would add a unit, not rewrite one
Outcome: additive incidental

## Question
Should dest grow an OpenSpec catalog so the ticket can “update the spec”?

## Inputs
- Criteria: "Update the spec and the README sentence that tells operators the prefix is safe whenever the middleware covers the host."
- Out of scope: "New trusted-IP exception or changing when trusted clients skip the bouncer."; "Changing how challenge/captcha/ban envelopes are written."; "Changing Traefik routing in e2e (`PathPrefix` to the AppSec listener)."; "Copying upstream `maxlerebourg/crowdsec-bouncer-traefik-plugin#403` as a patch."
- Units: `bouncer.go` `handleNextServeHTTP` — AppSec allow then next; dest has no `openspec/` directory.

## Mandate
Nothing names creating an OpenSpec catalog. Desired says update "the spec"; dest `main` has no `openspec/` (looked at worktree root). Out of scope does not decline a catalog either. Bootstrapping is a means to that sentence, so mandate stays incidental.

## Extent
Searched dest worktree root for `openspec` (directory absent), and `git ls-files openspec` is empty. There are no spec leaves and no callers of a catalog on dest. Adding `openspec/` would be a new unit, not a reshape of existing working structure. Extent moves from structural to additive.

## Outcome
Do not bootstrap `openspec/` on dest. README is the operator contract. Caller: `assumed` — skip catalog; document 404 in README only. Append a Deviations row (bounded/additive incidental reshape of “update the spec”).

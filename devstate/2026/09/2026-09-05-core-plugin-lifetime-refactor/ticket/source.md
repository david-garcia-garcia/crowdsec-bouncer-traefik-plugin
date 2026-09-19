# Separate plugin package and CrowdSecConnection vs Bouncer

IssueKey: 2026-09-05-core-plugin-lifetime-refactor
issueHost: local

## Spec

Separate the plugin into its own package.

Clearly separate the behavior/instance of the CrowdSecConnection (the component that keeps the cache, stream ticker, and related connection lifetime) vs the Bouncer (which simply handles what happens in a request for an incoming route).

This is a sensitive change/refactor. Test coverage must be exquisite.

Dedicated worktree from a freshly fetched master. Stop after explore so the design can be agreed before propose/implement.

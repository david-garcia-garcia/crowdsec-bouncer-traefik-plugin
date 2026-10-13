# Issues

- [x] take small  `knowledge/debt/2026-09-18-lapi-session-tests-race-on-shared-log-buffer.md` → deleted
  Why: that note exists only to describe this unfixed flake. This change fixes it.
  Taken: the note was never committed (untracked in the owner's checkout), so it is removed from that working tree rather than by this PR's diff.

- [ ] note large  `knowledge/debt/2026-09-18-test-log-sink-outside-pkg-lapi.md`
  Why: `pkg/appsec` and `pkg/logger` tests still capture into a bare `bytes.Buffer`, which the new spec leaf now covers; neither races today.

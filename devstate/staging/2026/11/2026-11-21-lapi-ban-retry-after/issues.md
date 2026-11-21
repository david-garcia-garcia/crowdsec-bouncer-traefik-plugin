# Issues

- [ ] note large  `knowledge/debt/2026-11-21-lookup-remediation-origin-id-always-zero.md`
  Why: `Store.LookupRemediation` always returns origin id 0 although the catalog promises it; callers lean on the origin name.
- [ ] note small  `knowledge/debt/2026-11-21-spec-map-missing-wafhop.md`
  Why: `openspec/specs/map.md` lacks the `wafhop` component on master, so `validate-spec-map` fails before any archive move.

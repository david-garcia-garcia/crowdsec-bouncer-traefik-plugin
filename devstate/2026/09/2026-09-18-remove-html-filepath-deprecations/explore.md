# Explore

## Concepts

Deprecated HTML-path settings still sit on `Config` and `plugin.New` still copies them. Ban fills `BanFilePath` only when that field is empty. Captcha overwrites `CaptchaFilePath` whenever `CaptchaHTMLFilePath` is non-empty. Template load and Content-Type inference already read only `BanFilePath` / `CaptchaFilePath`. `configuration.New` defaults those to `""` and `/captcha.html`. The two HTML-path fields are the only `Deprecated` settings on `Config`.

```
Traefik YAML / Docker label
        │
        ▼
 CreateConfig()  →  defaults BanFilePath="" CaptchaFilePath=/captcha.html
        │
        ▼
 mapstructure decode (no ErrorUnused)
        │
        ├─ banFilePath / captchaFilePath     → current fields
        ├─ banHtmlFilePath / captchaHtmlFilePath
        │     (or HTML-cased twins)         → Deprecated fields today
        │                                   → unused after field delete
        ▼
 plugin.New snapshot
        │
        ├─ dest: copy Deprecated → current (ban empty-guard, captcha overwrite)
        └─ wanted: no copy; current fields only
        ▼
 ValidateParams / GetTemplate
```

Closed PR #85 made captcha match the ban empty-guard and added a “current key wins” test. Owner declined that: the alias is the problem, not which key wins. A deprecated-only YAML would keep serving `/captcha.html` after an empty-guard, not the HTML-path file. This run must delete both fields and both `New` copies. Do not reuse #85, branch `2026-09-18-captcha-html-path-clobbers-file-path`, or an empty-guard alias test.

Traefik v3.7.11 `createConfig` does not set mapstructure `ErrorUnused`. Leftover keys are dropped. `New` cannot warn or copy them after the fields are gone. Operators who only set the old keys silently get CreateConfig defaults.

Prepare’s exact-tag scan missed HTML-cased leftovers that mapstructure still matches today (`captchaHTMLFilePath` = `CaptchaHTMLFilePath`). Dest README sample and the captcha / custom-captcha examples still use those spellings. Real e2e and mock captcha use `banHtmlFilePath` / `captchaHtmlFilePath`. Live OpenSpec custom-ban WHEN still names `banHtmlFilePath`. Mock custom-ban and the in-tree custom-ban example already use `banFilePath`. Archive OpenSpec may keep the old name. No product `_test.go` references the Deprecated fields.

This change only deletes the alias blocks before `ValidateParams`. It does not add `sync.Once` or package globals. `pkg/reclaim` and `std_go_reclaim` stay the holder for LAPI/AppSec. Identity (client address, Host, trust hop) is not reconstructed here.

## Decisions

- Delete `BanHTMLFilePath` and `CaptchaHTMLFilePath` (fields, json tags, comments) and both `plugin.New` alias blocks. No compatibility copy.
- Retarget every live in-tree leftover, including HTML-cased README/examples, to `banFilePath` / `captchaFilePath`.
- Leave archived OpenSpec history as-is.
- Prove current keys via existing e2e after YAML retarget. Do not add an empty-guard alias test.
- Propose FindSpecHost for the live e2e WHEN rename and any Config-surface SHALL. Do not add an alias SHALL.

## Open questions

- Q: After the Deprecated fields are deleted, does Traefik fail plugin construct on leftover `banHtmlFilePath` / `captchaHtmlFilePath` (and HTML-cased twins), or drop them?
  Decision: resolved — Traefik v3.7.11 `createConfig` does not set `ErrorUnused`; unused keys are ignored. `New` never sees them. Do not keep fields to catch leftovers. Written: `knowledge/research/ext_traefik_plugins_config-decode/`.
  By: explore

- Q: Should this run keep a quieter empty-guard alias so `captchaFilePath` wins when both keys are set (declined PR #85)?
  Decision: resolved — no. Owner declined #85: drop both Deprecated fields and both `New` copies. Do not reuse that branch, its empty-guard test, or a compatibility alias.
  By: explore

- Q: Who owns the template path after Traefik decode?
  Decision: resolved — Traefik’s mapstructure result on `CreateConfig` owns `BanFilePath` / `CaptchaFilePath`. `New` snapshots that into `prepared`. `ValidateParams` / `GetTemplate` read only those fields. Do not reconstruct the path from leftover YAML keys or from a peer alias.
  By: explore

- Q: Which live docs/examples still name the old keys, given prepare said README had none?
  Decision: resolved — dest README sample still has `captchaHTMLFilePath` / `banHTMLFilePath`; `examples/captcha` and `examples/custom-captcha` use `captchaHTMLFilePath`. Those match the Deprecated fields today (case-insensitive). Retarget them with the e2e YAML and the live `build_e2e_pester_crowdsec-stack` WHEN. Do not invent `examples/enhanced-decisions`.
  By: explore

- Q: May archived OpenSpec keep `banHtmlFilePath`?
  Decision: resolved — yes. Update the live spec only. `openspec/changes/archive/2026-09-05-add-real-e2e/` stays historical.
  By: explore

- Q: Should `New` log or reject leftover old keys after the fields are gone?
  Decision: resolved — no path exists; Traefik drops unused keys before `New`. Operators who only set the old keys get defaults (`BanFilePath` empty, `CaptchaFilePath` `/captcha.html`). Say that on the Operators line. Do not add a remain-map or warn hook.
  By: explore

- Q: Does this ticket need a CHANGELOG entry or catalog version bump?
  Decision: assumed — no CHANGELOG file on dest; do not invent one. Catalog version is a release job, not this change. Breaking for operators who still set only the old keys; state that on the PR Operators line.
  By: explore

- Q: Which spec leaf owns the Config-field deletion versus the e2e WHEN rename?
  Decision: assumed — propose runs FindSpecHost. Live `build_e2e_pester_crowdsec-stack` must rename the custom-ban WHEN key. `core_plugin_middleware_bouncer` does not name the Deprecated fields today; do not add an alias SHALL. Fold or new only if propose finds a Config-surface leaf that should say the old keys are gone.
  By: explore

- Q: How do we prove current keys still compile and serve without a new alias test?
  Decision: resolved — no `_test.go` references the Deprecated fields. After YAML retarget, existing real-stack custom-ban and mock captcha e2e are the serve proof. Do not add `TestNew_CaptchaFilePathWinsOverDeprecatedHTMLPath` or any empty-guard alias test. Do not touch template-load defaults (out of scope; empty `captchaFilePath` panic stays the existing debt).
  By: explore

- Q: Does deleting the `New` alias blocks change reclaim / process lifetime?
  Decision: resolved — no. Delete only the two copy blocks on `prepared` before `ValidateParams`. Keep the existing snapshot and bindCtx. Do not add `sync.Once` or package globals.
  By: explore

---
url: https://trycap.dev/guide/widget
title: Widget
fetched: 2026-09-06
authority: official
---

Web component `<cap-widget>`. Rust-flavoured WASM. Programmatic mode available.

CDN install: `<script type="module" src="https://cdn.jsdelivr.net/npm/cap-widget"></script>`. Pin version in production. `cdn.jsdelivr.net` blocked in some jurisdictions; npm install alternative. Package managers: pnpm/npm/bun `cap-widget`.

Required attribute `data-cap-api-endpoint`: for Standalone, `https://<your-instance>/<site-key>/`.

Form: widget inside `<form>` auto-injects hidden input; default hidden field name `cap-token` (`data-cap-hidden-field-name` overrides).

Events (CustomEvent):

| Event | Detail |
|---|---|
| `solve` | `{ token: string }` |
| `progress` | `{ progress: number }` |
| `error` | `{ message: string }` |
| `reset` | `{}` |

Attributes:

| Attribute | Description |
|---|---|
| `data-cap-api-endpoint` | Required. Cap endpoint URL |
| `data-cap-hidden-field-name` | Hidden token input name in form (default: `cap-token`) |
| `data-cap-worker-count` | Solver workers (default hardwareConcurrency or 8) |

Programmatic mode: `import Cap from "cap-widget"; const cap = new Cap({ apiEndpoint: "..." }); const { token } = await cap.solve();`

Quickstart page uses unpinned `@<version>` script without `type="module"`; widget page uses `type="module"` and unpinned CDN URL.

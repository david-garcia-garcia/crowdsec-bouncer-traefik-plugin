# Cap Standalone

Official Cap Standalone (trycap.dev) facts for integrating the self-hosted widget and server-side token verification in this product.

Fetched: 2026-09-06. Docs: trycap.dev guide (standalone, quickstart, widget).

## Deployment

Cap Standalone is the recommended self-hosted backend. Docker image **`tiago2/cap:latest`**, default port **3000**, requires **Redis/Valkey** (`REDIS_URL`). Runs on Bun (~50 MB idle). ([standalone](https://trycap.dev/guide/standalone/), extract `.sources/guide-standalone.md`)

Dashboard login uses **`ADMIN_KEY`** (≥32 characters recommended). After login, create a **site key** and its **secret key** in the dashboard. The instance must be **publicly reachable** from browsers. ([standalone](https://trycap.dev/guide/standalone/))

## Widget integration

Web component: **`<cap-widget>`**. ([widget](https://trycap.dev/guide/widget))

Required attribute:

```
data-cap-api-endpoint="https://<instance_url>/<site_key>/"
```

Both `<instance_url>` and `<site_key>` come from the dashboard. Trailing slash shown in all official examples. ([standalone](https://trycap.dev/guide/standalone/), [widget](https://trycap.dev/guide/widget))

Script load options:

| Source | Pattern |
|---|---|
| Quickstart CDN | `<script src="https://cdn.jsdelivr.net/npm/cap-widget@<version>"></script>` |
| Widget page CDN | `<script type="module" src="https://cdn.jsdelivr.net/npm/cap-widget"></script>` |

Pin **`@<version>`** in production; unpinned CDN is documented but not recommended. npm/pnpm/bun package **`cap-widget`** is an alternative when CDN is blocked. ([quickstart](https://trycap.dev/guide/), [widget](https://trycap.dev/guide/widget))

### Token delivery to the server

Inside a **`<form>`**, the widget auto-injects a hidden field. Default name **`cap-token`**; override with **`data-cap-hidden-field-name`**. ([widget](https://trycap.dev/guide/widget))

For SPAs or custom flows, listen for the **`solve`** CustomEvent; token is **`e.detail.token`** (shape `{ token: string }`). ([quickstart](https://trycap.dev/guide/), [widget](https://trycap.dev/guide/widget))

Programmatic (no visible widget): `new Cap({ apiEndpoint: "..." })` then `await cap.solve()` → `{ token }`. ([widget](https://trycap.dev/guide/widget))

## Server-side siteverify

Before trusting a submission, POST the token to:

```
https://<instance_url>/<site_key>/siteverify
```

Request (all official examples):

- Method: **POST**
- Header: **`Content-Type: application/json`**
- Body JSON: **`{ "secret": "<key_secret>", "response": "<captcha_token>" }`**
  - **`secret`** — site-key **secret key** from the dashboard (**not** `ADMIN_KEY`)
  - **`response`** — token from the widget (`cap-token` form field or `e.detail.token`)

Success response:

```json
{ "success": true }
```

([standalone](https://trycap.dev/guide/standalone/), [quickstart](https://trycap.dev/guide/))

### reCAPTCHA compatibility vs Content-Type

Marketing on the quickstart page states Cap's **`/siteverify` is compatible with reCAPTCHA's API** — change one URL, no rewrite. ([quickstart](https://trycap.dev/guide/))

**Conflict:** reCAPTCHA siteverify is commonly called with **`application/x-www-form-urlencoded`**. Every documented Cap example (curl, fetch, Python, PHP) uses **`Content-Type: application/json`** and a JSON body. No official page documents form-urlencoded for Cap.

**What this product must send:** follow the documented JSON POST above. Do **not** assume form-urlencoded works unless a stronger source proves it.

### Token lifetime

Tokens are **single-use**. Verify each token once; resubmitting the same token should fail (official end-to-end check). ([quickstart](https://trycap.dev/guide/))

## References

- Official: [Cap Standalone](https://trycap.dev/guide/standalone/), [Quickstart](https://trycap.dev/guide/), [Widget](https://trycap.dev/guide/widget)
- Extracts: `.sources/`

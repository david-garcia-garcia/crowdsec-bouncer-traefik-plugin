# Source (issueHost: local)

Caller: chat request, 2026-11-14.

## Human text

> haz un buen análisis, y luego un PR hacia master usando opd-workflow. Asegúrate de que en el delivery card de los PR se mencionen todos los issues y pr's de upstream relacionados con esto.

"Esto" is problem 3 of `upstream-review-2026-11-14.md` (main checkout, untracked review document), after the caller asked whether `captcha` is an AppSec response type CrowdSec supports or something upstream invented.

## Problem 3 as written in the review (verbatim)

### 3. Una respuesta de AppSec sin body acaba en página en blanco · P2

- [ ] **Si AppSec devuelve una acción que no es `ban` ni `challenge` (p. ej. `captcha`) sin `user_body_content`, el visitante recibe una página vacía.**

**Origen upstream:**
- PR #343: soporte de bot detection. Cualquier acción que no sea `ban` ni `challenge` termina en ban.
- PR #403, sub-fix (c): una acción `captcha` de AppSec sirve el captcha configurado. Issue relacionada: #357.

**Contexto:** una regla o un hook de AppSec puede pedir `captcha` (`SetRemediation("captcha")`). Según #402, CrowdSec envía esa acción **sin body**. Upstream la resuelve con su captcha propio.

**Situación en el fork (verificado en `pkg/bouncer/bouncer.go:475-532`):**
- Por diseño, el fork reenvía tal cual las acciones que no son `ban` (decisión documentada en `knowledge/devdocs/core_plugin_appsec.md:30` y en `openspec/specs/core_plugin_appsec_bot-detection/spec.md`).
- Si no hay body, solo escribe el código de estado: **200 en blanco** si AppSec no trae `http_status`, o **403 en blanco** si lo trae. El backend no se alcanza, así que no es un fail-open, pero el visitante no ve ni captcha ni página de ban.
- El fork ya aplica fail-closed a un `challenge` sin body (página de ban). Simplemente no lo extiende a las demás acciones.

**Propuesta:**
1. Comprobar en el e2e real (CrowdSec 1.8.x con una regla `SetRemediation("captcha")`) qué sobre devuelve AppSec.
2. Como mínimo, que **cualquier acción reenviada sin `user_body_content` sirva la página de ban**, igual que ya se hace con el challenge sin body.
3. Actualizar el spec y el devdoc con la decisión.

**A decidir:**
- Si además se sirve el captcha configurado ante `captcha` de AppSec, como upstream. Implica revertir una decisión de spec, revisar el POST del formulario (pasa antes por AppSec) y su interacción con el marcador `crowdsec_captcha_challenge=v1`.
- Si `http_status` 0 debe seguir convirtiéndose en 200 cuando sí hay body.

## Findings from the chat turn before this request

Read from source, not docs summaries:

- CrowdSec `crowdsecurity/crowdsec` `main` @ `e20782bb` (2026-11-13), `pkg/appsec/appsec.go:97-102`: `BanRemediation = "ban"`, `CaptchaRemediation = "captcha"`, `AllowRemediation = "allow"`, `ChallengeRemediation = "challenge"`. `:1062-1066` validates `default_remediation` against those four with the comment `// those are the officially supported remediation(s)`. v1.6.0 already had `case "ban", "captcha", "log": //those are the officially supported remediation(s)`.
- `GenerateResponse` (`appsec.go:2065-2110`) fills `user_body_content`, `user_cookies`, `user_headers` only for `challenge`. `ban` and `captcha` carry `action` and `http_status` only (`http_status` defaults to `UserBlockedHTTPCode` = 403). Any other string set through `SetRemediation` (`waf_helpers.go:358` → `SetAction`, no validation) takes the `default` branch: same status logic, no body.
- `crowdsec-docs`: `appsec/hooks.md:306` "Any other values (including `ban` and `captcha`) are transmitted as-is to the remediation component"; `appsec/protocol.md:112` and `bot_detection/challenge_protocol.md:13` call `ban` and `captcha` verdicts "the remediation component renders from its own templates"; `rules_examples.md:725,808` use `SetRemediation('captcha')`.
- `lua-cs-bouncer` @ `4aad1df`: AppSec `captcha` is served with its own captcha; the captcha submission is validated before querying AppSec; unsupported remediations fall back to `FALLBACK_REMEDIATION` (ban by default); `challenge` without a body bans.

## Upstream references (maxlerebourg/crowdsec-bouncer-traefik-plugin)

- Issue #357 — "[FEATURE] Add support for "captcha"-type solutions to the AppSec module." Closed 2026-11-06.
- Issue #402 — "[BUG] Bot detection: remaining gaps with CrowdSec's challenge protocol", point 3 "An AppSec `captcha` action is turned into a ban". Closed by #403.
- PR #403 — "🐛 close the remaining gaps with CrowdSec's bot-detection protocol", commit 3 "serve the captcha when AppSec answers with a captcha action". Review note: the captcha form POST goes through AppSec first and is validated only when AppSec answers that POST with captcha again; checking the submission before AppSec (lua) was left out.
- PR #343 — "add the bot detection feature to the crowdsec traefik bouncer": relays `challenge`, bans every other non-allow action.
- Issue #389 — bot-detection challenge never resolved through the plugin (context for #343).
- Issue #354 / PR #428 — captcha submitted again after it was solved reaches the backend (405); the fork solved it with the `crowdsec_captcha_challenge=v1` marker (#201).

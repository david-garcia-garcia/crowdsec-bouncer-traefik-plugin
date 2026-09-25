# Provider allowlist lives on captcha-enterprise-config

IssueKey: 2026-09-24-eucaptcha-provider
Size: large
Action: note

## Why this follow-up

Live leaf `core_plugin_middleware_captcha-enterprise-config` names recaptcha-enterprise knobs, but it also owns the full `captchaProvider` allowlist (unknown-token scenario). This change folds `eucaptcha` onto that same leaf.

## Why it was not taken

Unattended take is only small rows on files this run created. Renaming that leaf would move archive history and every fold that already points at it.

## Risks

Later provider tokens keep folding into a leaf whose name hides the allowlist.

## Context

Current: `openspec/specs/core_plugin_middleware_captcha-enterprise-config`
Proposed: keep the id; a later change could split the allowlist into a leaf that names provider tokens.

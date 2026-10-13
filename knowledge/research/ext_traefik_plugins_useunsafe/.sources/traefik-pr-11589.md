---
url: https://github.com/traefik/traefik/pull/11589
title: "Ability to enable unsafe in yaegi through plugin manifest (traefik/traefik#11589)"
fetched: 2026-09-05
authority: vendor
---

The PR that introduced `useUnsafe`. Author `Rydez`; merged by `traefiker` 2025-04-25T09:26:05Z.
Merge commit `8f37c8f0c54d5bba62eadbb7cd633267de939c32`. +45 −10 across 7 files.
Labels: `kind/enhancement`, `size/S`, `area/plugins`. Fixes traefik/traefik#11588
("Ability to use yaegi's `unsafe.Symbols`").

## Stated purpose

> This PR provides a way to enable the use of the `unsafe` package in the go standard library
> within yaegi by adding a flag in the plugin manifest.

Motivation, from the author:

> Otherwise, I need to create a wasm plugin which means I can't use go's native request and
> response types, and the request context is not preserved.

This frames `useUnsafe` as the alternative to *wasm*, i.e. a way to stay on Yaegi. It is not a
path to a compiled native plugin.

## Maintainer review — why the second opt-in exists

`rtribotte`, 2025-03-14:

> Given the nature of the `unsafe` package, we are concerned about the awareness of Traefik users
> and we want to make sure that we give them full control over whether to allow the use of the
> `unsafe` package. Also, since the plugin mechanism relies on several parts, changes are also
> needed in the Piceus repository and on the catalog frontend repository.
>
> Considering that, we think the plan would be to:
>
> - Add a flag to the plugin manifest to use of the `unsafe` package (as you have started to
>   implement). This flag controls the Yaegi configuration on plugin startup in Traefik.
> - The manifest flag would also be a marker for Piceus, when referencing the plugin, to mark it
>   as "unsafe" and also bypass the usual checks (running the `New` and `CreateConfig` func).
> - A plugin marked as "unsafe" must be identifiable in the catalogue ui.
> - **Add an option to the plugin settings configuration to allow the use of the `unsafe` package.
>   It's the opt-in part for the Traefik user. If this option is missing, the plugin should fail
>   to start.**

`juliens`, 2025-04-11: "I made the changes for the settings part, and I opened the PR on piceus
and on the plugin-service."

## Merge note — catalog was not ready at merge time

`juliens`, 2025-04-25T09:26:49Z:

> I've merged this PR, so unsafe now works with local plugins.
>
> To support plugins using unsafe in the catalog, we'll need to wait for piceus#110 and
> plugin-service#69 to be merged.

## Cross-reference

The PR timeline records: "Referenced by issue #257: [FEATURE] Move to a maintained and scalable
Redis Go library" — the same motivation as this ticket.

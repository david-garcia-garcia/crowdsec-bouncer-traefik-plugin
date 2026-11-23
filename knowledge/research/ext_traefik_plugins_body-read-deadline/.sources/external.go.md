---
url: https://github.com/traefik/traefik/blob/v3.7.19/pkg/plugins/external.go
ref: traefik/traefik@v3.7.19:pkg/plugins/external.go
title: Traefik plugin handler wrapping — entryWriter and exitWriter
fetched: 2026-11-23
authority: source
---

L14-20 doc comment on `wrapExternal`: builds a plugin handler (Yaegi, Wasm) around next. "The external handler receives a ResponseWriter implementing http.Flusher and http.Hijacker, as such code asserts them directly instead of using http.ResponseController. The ResponseWriter it gives to next may not implement Unwrap: it is wrapped to reach the deadlines, full duplex and hijacking of the ResponseWriter given to the external handler, when the external ResponseWriter does not support them. Flush is left to the external ResponseWriter: a buffering writer must not be flushed past."

L31-39 `wrapExternalWith`: `external := build(exitHandler(next))`; returns `entryHandler(external)`.

L41-46 `entryHandler`: `entry := newEntryWriter(rw)`; `external.ServeHTTP(entry, req.WithContext(context.WithValue(ctx, entryWriterKey{}, entry)))`. The plugin's `ServeHTTP` receives the `entryWriter`.

L48-57 `exitHandler`: if the writer the plugin passes to next is the entry writer itself, next gets it unchanged; otherwise next gets `&exitWriter{ResponseWriter: rw, entry: entry}`.

L60-93 `entryWriter`: embeds `http.ResponseWriter`, holds `rc *http.ResponseController` on the inner writer; `Flush`/`FlushError`/`Hijack` go through `rc`; `Unwrap()` returns the inner writer (L92). It has no `SetReadDeadline` method, so `http.ResponseController` on it walks `Unwrap`.

L96-146 `exitWriter`: `SetReadDeadline`, `SetWriteDeadline`, `EnableFullDuplex` and `Hijack` first try `http.NewResponseController(w.ResponseWriter)` (the writer the plugin passed on) and fall back to `http.NewResponseController(w.entry)` when that returns `http.ErrNotSupported`; `Unwrap()` returns the plugin's writer (L143).

`pkg/plugins/middlewareyaegi.go` L62-65: Yaegi `newHandler` returns `wrapExternal(next, ... b.newPluginHandler ...)`. `pkg/plugins/middlewarewasm.go` L55 uses `wrapExternalWith`.

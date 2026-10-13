---
url: https://github.com/traefik/traefik/blob/faa1eb590646aed94e561e24a59be0c47353ae95/pkg/plugins/middlewareyaegi.go
title: pkg/plugins/middlewareyaegi.go createConfig
fetched: 2026-09-18
authority: source
ref: github.com/traefik/traefik@faa1eb590646aed94e561e24a59be0c47353ae95:pkg/plugins/middlewareyaegi.go
---

createConfig: fnCreateConfig.Call(nil); must return exactly one value. That pointer is mapstructure DecoderConfig.Result. Empty config map returns the default pointer unchanged.

Non-empty map uses DecoderConfig with DecodeHook StringToSliceHookFunc(","), WeaklyTypedInput true, Result = that pointer. ErrorUnused is not set. TagName is not set. NewDecoder + Decode; failure wraps as "failed to decode configuration".

newHandler then calls New with that same decoded pointer as the config argument.

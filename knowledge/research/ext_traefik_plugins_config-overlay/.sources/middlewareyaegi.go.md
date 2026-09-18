---
url: https://github.com/traefik/traefik/blob/faa1eb590646aed94e561e24a59be0c47353ae95/pkg/plugins/middlewareyaegi.go
title: pkg/plugins/middlewareyaegi.go createConfig
fetched: 2026-09-18
authority: source
ref: github.com/traefik/traefik@faa1eb590646aed94e561e24a59be0c47353ae95:pkg/plugins/middlewareyaegi.go
---

createConfig: fnCreateConfig.Call(nil); must return exactly one value (vConfig).
Empty operator map (len(config)==0) returns vConfig unchanged.
Non-empty map: mapstructure.DecoderConfig{DecodeHook: StringToSliceHookFunc(","), WeaklyTypedInput: true, Result: vConfig.Interface()}.
ZeroFields and TagName are not set.
decoder.Decode(config) writes the operator map onto the CreateConfig pointer, then returns that pointer to New.

---
url: https://github.com/mitchellh/mapstructure/blob/v1.5.0/mapstructure.go
title: DecoderConfig.ZeroFields
fetched: 2026-09-18
authority: source
ref: github.com/mitchellh/mapstructure@v1.5.0:mapstructure.go
---

ZeroFields bool: if true, zero fields before writing them (a map is emptied then filled). If false, a map is merged.
ZeroFields is a zero-value bool; default is false.
TagName empty defaults to "mapstructure".
A nil input value is not written unless ZeroFields is set.
Missing keys in the source map are not applied to Result; existing Result values remain.

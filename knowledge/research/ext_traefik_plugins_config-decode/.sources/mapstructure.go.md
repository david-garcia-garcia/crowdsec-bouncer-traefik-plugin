---
url: https://github.com/mitchellh/mapstructure/blob/v1.4.1/mapstructure.go
title: mapstructure DecoderConfig unused keys
fetched: 2026-09-18
authority: source
ref: github.com/mitchellh/mapstructure@v1.4.1:mapstructure.go
---

Remainder Values: unmapped keys in the source are silently ignored by default. Error by setting ErrorUnused. Metadata can collect unused keys. A ",remain" tag can collect leftovers into a map.

DecoderConfig.ErrorUnused: if true, unused original-map keys are an error ("extra keys"). Type is bool; zero value false.

When ErrorUnused is true and unused keys remain, decode appends: "'%s' has invalid keys: %s".

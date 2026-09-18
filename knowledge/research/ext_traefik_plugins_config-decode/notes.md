# Plugin config decode

Traefik Yaegi middleware `createConfig` mapstructure-decodes the named middleware’s config map into the pointer `CreateConfig` returned. Unused keys do not fail that decode. `New` never sees a leftover key after the matching struct field is gone.

## Decoder settings

`createConfig` calls `CreateConfig` with no arguments. An empty config map returns that pointer unchanged. A non-empty map builds:

```go
cfg := &mapstructure.DecoderConfig{
	DecodeHook:       mapstructure.StringToSliceHookFunc(","),
	WeaklyTypedInput: true,
	Result:           vConfig.Interface(),
}
```

`ErrorUnused` is not set. Decode failure wraps as `failed to decode configuration`.

Owner: `github.com/traefik/traefik@faa1eb590646aed94e561e24a59be0c47353ae95:pkg/plugins/middlewareyaegi.go` (`createConfig`). Tag `v3.7.11`. Extract: `.sources/middlewareyaegi.go.md`.

This repo’s real-stack e2e pins `traefik:v3.7.11`. Owner: `openspec/specs/build_e2e_pester_crowdsec-stack/spec.md`.

## Unused keys are dropped

mapstructure: unmapped source keys are silently ignored unless `ErrorUnused` is true. The zero value is false. Owner: `github.com/mitchellh/mapstructure@v1.4.1:mapstructure.go` (package comment “Remainder Values”; `DecoderConfig.ErrorUnused`). Extract: `.sources/mapstructure.go.md`.

Traefik v3.7.11 imports `github.com/mitchellh/mapstructure v1.5.1-0.20231216201459-8508981c8b6c`. Owner: `github.com/traefik/traefik@faa1eb590646aed94e561e24a59be0c47353ae95:go.mod`. Extract: `.sources/go.mod.md`.

So a YAML or Docker label that still sets `banHtmlFilePath` / `captchaHtmlFilePath` (or the HTML-cased twins `banHTMLFilePath` / `captchaHTMLFilePath`) after those fields are deleted does not fail plugin construct. The values never reach `New`. `CreateConfig` defaults stay: this plugin’s `BanFilePath` `""`, `CaptchaFilePath` `/captcha.html`.

## Key match is the field name

Traefik does not set `TagName`. mapstructure then matches the field name, case-insensitive, not the `json` tag string as a separate spelling. `captchaHTMLFilePath` and `captchaHtmlFilePath` both map to `CaptchaHTMLFilePath`. Neither maps to `CaptchaFilePath` (`captchahtmlfilepath` ≠ `captchafilepath`). Same for ban: `banHTMLFilePath` / `banHtmlFilePath` ≠ `BanFilePath`.

Owner: mapstructure default match plus Traefik `DecoderConfig` above. This plugin’s tags: `this-repo` `pkg/configuration/configuration.go` (`BanHTMLFilePath` `json:"banHtmlFilePath,omitempty"`, `CaptchaHTMLFilePath` `json:"captchaHtmlFilePath,omitempty"`).

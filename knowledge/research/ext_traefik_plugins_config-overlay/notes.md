# Yaegi plugin config overlay

Traefik builds a plugin config by calling `CreateConfig`, then mapstructure-decoding the operator map onto that same pointer. Missing keys are not zeroed.

## CreateConfig is the decode destination

`createConfig` calls `CreateConfig` with no arguments and uses the returned pointer as `mapstructure.DecoderConfig.Result`. An empty operator map returns that pointer unchanged.

When the map is non-empty, Traefik builds a decoder with `WeaklyTypedInput: true`, a comma `StringToSlice` hook, and that same `Result`. It does not set `ZeroFields` or `TagName`.

Owner: `github.com/traefik/traefik@faa1eb590646aed94e561e24a59be0c47353ae95:pkg/plugins/middlewareyaegi.go` (`createConfig`). Extract: `.sources/middlewareyaegi.go.md`.

## Missing keys keep CreateConfig values

mapstructure `ZeroFields` defaults to false. A key absent from the operator map is not written. Fields already set on `Result` stay.

Owner: `github.com/mitchellh/mapstructure@v1.5.0` (`DecoderConfig.ZeroFields`). Extract: `.sources/mapstructure.go.md`.

This plugin: `CreateConfig` returns `configuration.New()`, which sets `CaptchaFilePath` to `/captcha.html` and `BanFilePath` to `""`. A Traefik YAML/label map that sets only `captchaHtmlFilePath` therefore arrives at `New` with `CaptchaFilePath` still `/captcha.html`.

Owner: `this-repo` `plugin.go` (`CreateConfig`), `pkg/configuration/configuration.go` (`New`).

---
url: https://github.com/traefik/traefik/blob/faa1eb590646aed94e561e24a59be0c47353ae95/pkg/plugins/middlewareyaegi.go
title: pkg/plugins/middlewareyaegi.go
fetched: 2026-09-05
authority: source
ref: github.com/traefik/traefik@faa1eb590646aed94e561e24a59be0c47353ae95:pkg/plugins/middlewareyaegi.go
---

newYaegiMiddlewareBuilder: if basePkg == "", basePkg = strings.ReplaceAll(path.Base(imp), "-", "_"). Then i.Eval(basePkg+".New") and i.Eval(basePkg+".CreateConfig"). Failure wraps as "failed to eval New" / "failed to eval CreateConfig".
createConfig: fnCreateConfig.Call(nil); must return exactly one value. That pointer is mapstructure DecoderConfig.Result. Empty config map returns the default pointer unchanged.
newHandler: Call New with (ctx, next, cfg, middlewareName). First return must be http.Handler; second if present must be error or nil.
YaegiMiddleware.NewHandler delegates to newHandler with the stored config pointer (CreateConfig result after decode).
newInterpreter: interp.New(Options{GoPath: goPath, Env: os.Environ(), ...}); i.Use(stdlib.Symbols); then i.Eval(`import "<manifest.Import>"`).

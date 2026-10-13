---
url: https://github.com/traefik/traefik/blob/faa1eb590646aed94e561e24a59be0c47353ae95/pkg/server/router/router.go
title: pkg/server/router/router.go
fetched: 2026-09-05
authority: source
ref: github.com/traefik/traefik@faa1eb590646aed94e561e24a59be0c47353ae95:pkg/server/router/router.go
---

buildHTTPHandler: qualify router.Middlewares names; BuildMiddlewareChain(ctx, router.Middlewares); chain.Extend(*mHandler).Then(nextHandler). Then() runs the alice constructors, which instantiate each named middleware for this router handler.
buildRouterHandler: if routerHandlers[routerName] already exists, return it. Otherwise buildHTTPHandler and store. So New is per router-handler build on that Manager, not per request.

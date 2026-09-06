# Cf-Ray HTTP header

Cloudflare's `Cf-Ray` (Ray ID) is a hashed request identifier Cloudflare adds on proxied traffic. Example from official docs: `Cf-Ray: 230b030023ae2822-SJC`.

Owner: [Cloudflare HTTP headers](https://developers.cloudflare.com/fundamentals/reference/http-headers/#cf-ray). Extract: `.sources/http-headers.md`.

## Shape

The documented example is 16 hexadecimal characters, a hyphen, then a three-letter data-center code (IATA-style, e.g. `SJC`). Official text: a hashed value that encodes information about the data center and the visitor's request. The three-letter code is the data center processing the request when the header is shown as a response header.

This plugin has no Cloudflare colo. A built-in remediation TraceID can resemble the 16-hex prefix. Inventing a fake three-letter colo would imply a Cloudflare location this process does not have.

## Request vs response

Cloudflare sends `Cf-Ray` to the origin and returns the same value to the visitor. Argo Smart Routing / Tiered Cache may change the three-letter code to the colo that connects to origin, not the ingress colo.

Owner: same page, Request headers `Cf-Ray` and Response headers `Cf-Ray`.

## Ownership

`Cf-Ray` is owned by Cloudflare's edge when that hop is in front of Traefik. Traefik does not generate it. This plugin must not reconstruct or copy `Cf-Ray` from incoming hops when the operator asked for a built-in remediation TraceID.

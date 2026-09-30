---
url: https://pkg.go.dev/net/url#Parse
title: net/url Parse
fetched: 2026-09-30
authority: official
---

Parse parses a raw url into a URL structure.

The url may be relative (a path, without a host) or absolute (starting with a scheme). Trying to parse a hostname and path without a scheme is invalid but may not necessarily return an error, due to parsing ambiguities.

CrowdSec request.go calls this Parse on X-Crowdsec-Appsec-Uri. A path-only / origin-form value such as `/foo` or `/login` is a relative URL: no scheme in the input, so URL.Scheme is empty.

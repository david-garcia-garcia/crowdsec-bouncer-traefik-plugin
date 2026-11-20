[Documentation](../README.md) › [How-to](README.md) › Match a country or an ASN

# Match a country or an ASN

`bouncerDecisionScopeHeaders` reads the country or ASN from a header you trust; the plugin does not geolocate. `lapiStreamScopes` asks LAPI to include those decisions in the stream:

```yaml
bouncerDecisionScopeHeaders:
  Country: CF-IPCountry
  AS: CF-ASN
lapiStreamScopes:
  - country
  - as
```

`lapiStreamScopes` goes on the middleware that connects to LAPI (`lapiEnabled: true`). `bouncerDecisionScopeHeaders` goes on every middleware that protects a router. How each scope is compared is described in [Decisions](../concepts.md#decisions). See [examples/geoenrich-decisions](../../examples/geoenrich-decisions/README.md).

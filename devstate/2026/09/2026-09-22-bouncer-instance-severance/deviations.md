# Deviations

- [x] taken  subscribe-only YAML uses owner flags false
  Why: requirement F3 / T2 subscriber sketch set `crowdsecLapiEnabled: true` with no key, which `ValidateParams` rejects because a true owner flag must Open. Built: `enabled: true`, owner flags false, instance names set (Open-vs-subscribe table).
  Cost: README and e2e use that table, not the sketch that would fail New.
  By: implement

# Specs
change: retarget-plugin-module-path

FindSpecHost (before each folder write):

```
verdicts:
  - { deltaId: yaegi-catalog-import, fold, core_plugin_middleware_bouncer, high, candidates: [core_plugin_middleware_bouncer] }
  - { deltaId: ci-checkout-module-path, fold, build_ci_github_module-path, high, candidates: [build_ci_github_module-path, build_ci_github_race-detector] }
  - { deltaId: ci-checkout-race, fold, build_ci_github_race-detector, high, candidates: [build_ci_github_race-detector, build_ci_github_module-path] }
  - { deltaId: traefik-local-plugin-install, new, core_plugin_middleware_local-plugin, high, candidates: [core_plugin_middleware_bouncer, build_e2e_pester_crowdsec-stack] }
```

- added core_plugin_middleware_local-plugin
- modified core_plugin_middleware_bouncer
- modified build_ci_github_module-path
- modified build_ci_github_race-detector

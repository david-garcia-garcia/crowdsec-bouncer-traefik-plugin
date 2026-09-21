# Specs
change: add-real-e2e

verdicts:
  - { deltaId: pester-e2e-suite, new, spec-id: build_e2e_pester_crowdsec-stack, confidence: high, candidates: [build_e2e_docker_crowdsec-stack] }
  - { deltaId: yaegi-checkout-path, new, spec-id: build_ci_github_module-path, confidence: high, candidates: [] }

- added build_e2e_pester_crowdsec-stack
- added build_ci_github_module-path

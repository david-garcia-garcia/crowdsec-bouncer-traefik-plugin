# Specs
change: redirect-solved-captcha-form-post

verdicts:
  - deltaId: captcha-solved-form-post
    fold|new: new
    spec-id: core_plugin_captcha_solved-form-post
    confidence: high
    candidates:
      - core_plugin_middleware_instance-reclaim
      - core_plugin_appsec_failure-action
    why: no captcha leaf exists; middleware reclaim and AppSec failure-action are other jobs

- added core_plugin_captcha_solved-form-post

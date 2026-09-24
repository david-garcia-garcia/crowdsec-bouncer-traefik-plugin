# Standards

1. [hard] Leave a trail — `pkg/captcha/captcha.go:1` — package comment still names a siteverify client after New pairs assessments
   Fix: Name the package (and `HTTPClientForTest`) as the captcha Client that holds a widget and a verifier
   Status: done
   Argument: package and HTTPClientForTest comments now name the captcha Client that holds a widget and a verifier.
   Quote:
      ```
      // Package captcha is the reclaim value for one named captcha siteverify client.
      ```
2. [hard] std_go_logger_debug-attrs — `pkg/captcha/captcha.go:401` — siteverify decode and assessments unmarshal now log at Error; the Gotcha keeps parse `error` attributes at Debug
   Fix: Log verifier JSON decode/unmarshal at Debug; do not fold those parse failures into `captcha:Validate` Error
   Status: done
   Argument: Validate logs verifier errors at Debug, not Error.
   Quote:
      ```
      passed, err := c.verifier.Pass(token, remoteIP)
      if err != nil {
      	c.log.Error("captcha:Validate", "error", err)
      	return None, err
      }
      ```
3. [hard] Leave a trail — `pkg/captcha/session.go:134` — `newOwnerClient` comment still says siteverify after it passes `Enterprise` and may pair assessments
   Fix: Say it constructs the captcha Client (widget, verifier, template, gate) for one owner Open
   Status: done
   Argument: newOwnerClient comment names widget, verifier, template, and gate.
   Quote:
      ```
      // newOwnerClient constructs the siteverify client, template, and gate for one owner Open.
      ```
4. [hard] Leave a trail — `knowledge/devdocs/core_plugin_middleware_captcha-siteverify.md:15` — packet still names `Client.validateBody` after the field moved onto `siteverifyVerifier`
   Fix: Name `siteverifyVerifier.validateBody` and list `pkg/captcha/siteverify.go` in Key files
   Status: done
   Argument: siteverify packet names siteverifyVerifier.validateBody and lists siteverify.go.
   Quote:
      ```
      Encode from `Client.validateBody` (custom-only).
      ```

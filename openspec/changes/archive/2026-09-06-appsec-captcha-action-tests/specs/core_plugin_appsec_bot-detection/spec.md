## ADDED Requirements

### Requirement: AppSec captcha envelope is parsed and relayed
When AppSec returns JSON with a non-empty `action` of `captcha`, `appsec.Client.Query` SHALL return that structured result with a nil error. The bouncer SHALL write `http_status`, `user_headers`, `user_cookies` (as `Set-Cookie`), and `user_body_content` to the client and MUST NOT call `next`. The bouncer MUST NOT use `pkg/captcha` for this envelope. Empty `user_body_content` SHALL still write `http_status` to the client; it MUST NOT substitute the operator ban page. The remediation custom header, when configured, SHALL be set to `captcha`.

#### Scenario: Captcha JSON is parsed
- **WHEN** AppSec returns HTTP 403 with `{"action":"captcha","http_status":403,"user_body_content":"<html>captcha</html>"}`
- **THEN** `Query` returns a nil error and a result whose `action` is `captcha`, `http_status` is 403, and `user_body_content` is that HTML

#### Scenario: Captcha HTML and cookie are served
- **WHEN** AppSec returns a parseable `action` `captcha` with `http_status` 403, HTML body, Content-Type, and a Set-Cookie value
- **THEN** the client receives that status, headers, cookie, and body, the backend is not called, and the remediation custom header is `captcha`

#### Scenario: Empty captcha body still relays status
- **WHEN** AppSec returns `{"action":"captcha","http_status":403}` with no `user_body_content`
- **THEN** the client status is 403, the body is empty, and the operator ban page is not used

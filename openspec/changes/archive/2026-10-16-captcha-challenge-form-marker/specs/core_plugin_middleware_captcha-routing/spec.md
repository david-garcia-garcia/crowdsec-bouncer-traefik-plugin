## MODIFIED Requirements

### Requirement: Solved captcha-form POST does not reach origin
When captcha kind applies and `Check` is true, a captcha-form POST SHALL receive `302 Found` to the same request URL. The handler MUST NOT forward that POST to origin. A captcha-form POST is a POST that carries leftover-form marker name `crowdsec_captcha_challenge` with value `v1`. Detection MUST NOT treat a provider response field as leftover proof. A GET that only carries the leftover-form marker or a provider field in the query is not a form POST. An ordinary POST that does not carry that marker SHALL still reach origin after `Check` is true, with its body unchanged, even when a provider response field is non-empty.

#### Scenario: Duplicate-tab form POST redirects
- **WHEN** captcha kind applies
- **AND** `Check` is true
- **AND** the request is POST
- **AND** leftover-form marker `crowdsec_captcha_challenge` equals `v1`
- **THEN** the response is `302 Found` to the same URL
- **AND** origin MUST NOT receive the POST

#### Scenario: Ordinary POST after solve reaches origin
- **WHEN** captcha kind applies
- **AND** `Check` is true
- **AND** the request is POST
- **AND** leftover-form marker `crowdsec_captcha_challenge` is absent or not `v1`
- **THEN** the request is passed to origin (AppSec still runs when enabled)

#### Scenario: Application POST with a vendor token reaches origin
- **WHEN** captcha kind applies
- **AND** `Check` is true
- **AND** the request is POST
- **AND** a provider response field is non-empty
- **AND** leftover-form marker `crowdsec_captcha_challenge` is absent
- **THEN** the request is passed to origin with its body unchanged
- **AND** the response MUST NOT be `302 Found`

### Requirement: Captcha-form detection never costs origin its body
Captcha-form detection runs on requests that may still be forwarded, so it SHALL be its own reader, separate from the first-verify provider-token reader used when the plugin answers the request itself. The two callers MUST NOT share one helper. After `Check` is true, detection SHALL look up leftover-form marker `crowdsec_captcha_challenge` with value `v1` and MUST NOT look up a provider response field for that answer. Detection SHALL inspect at most 64KiB of body; a request whose declared or actual body exceeds that SHALL NOT be treated as a captcha form. It SHALL read `application/x-www-form-urlencoded` and `multipart/form-data` bodies, and SHALL read a body with no usable `Content-Type` as urlencoded. When the form was already parsed upstream, detection SHALL answer from the parsed values instead of rereading the body. Whenever the answer is no, the body and `Content-Length` SHALL be left readable so origin receives the request intact.

#### Scenario: Over-maximum POST reaches origin unchanged
- **WHEN** `Check` is true and the request is a POST whose body is larger than 64KiB
- **AND** that body contains leftover-form marker name `crowdsec_captcha_challenge`
- **THEN** the request is not treated as a captcha form
- **AND** origin receives every byte of the original body

#### Scenario: Multipart captcha form is detected
- **WHEN** captcha kind applies and `Check` is true
- **AND** the request is a `multipart/form-data` POST carrying leftover-form marker `crowdsec_captcha_challenge` equal to `v1`
- **THEN** the response is `302 Found`
- **AND** origin MUST NOT receive the POST

#### Scenario: Unknown content length behaves sanely
- **WHEN** the request declares no content length
- **THEN** a body within 64KiB is still inspected for leftover-form marker `crowdsec_captcha_challenge`
- **AND** a body over 64KiB is not treated as a captcha form and reaches origin unchanged

#### Scenario: Already-parsed form is answered from parsed values
- **WHEN** an upstream handler already parsed the POST form
- **THEN** detection answers from the parsed leftover-form marker without rereading the body

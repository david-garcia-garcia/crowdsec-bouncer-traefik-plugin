# Assessments API

How official Google Cloud reCAPTCHA Enterprise `projects.assessments.create` authenticates a REST call and what request/response JSON it uses.

Fetched: 2026-09-24.

## Endpoint

`POST https://recaptchaenterprise.googleapis.com/v1/{parent=projects/*}/assessments` with `parent` = `projects/{project}`. ([Method: projects.assessments.create](https://cloud.google.com/recaptcha/docs/reference/rest/v1/projects.assessments/create), extract `.sources/rest-projects-assessments-create.md`)

The website guide writes the same URL as `POST https://recaptchaenterprise.googleapis.com/v1/projects/PROJECT_ID/assessments`. ([Create assessments for websites](https://cloud.google.com/recaptcha/docs/create-assessment-website), extract `.sources/create-assessment-website.md`)

## Auth: `X-Goog-Api-Key` and `?key=`

`projects.assessments.create` accepts API keys. ([Authenticate to Fraud Defense](https://cloud.google.com/recaptcha/docs/authentication), extract `.sources/authentication.md`)

The reCAPTCHA REST sample sends the key only as a query parameter: `POST .../assessments?key=API_KEY`. It does not mention a header. `API_KEY` is described as associated with the current project. ([Create assessments for websites](https://cloud.google.com/recaptcha/docs/create-assessment-website), extract `.sources/create-assessment-website.md`)

Across all Google REST APIs, the API-key system parameter is either query `$key`/`key` or header `X-Goog-Api-Key`. ([System parameters](https://cloud.google.com/apis/docs/system-parameters), extract `.sources/system-parameters.md`)

Cloud-wide REST guidance prefers the header (`X-goog-api-key` in that page's sample) and allows `?key=` only when the header cannot be used. Those samples are Translation / Natural Language, not reCAPTCHA. ([Use API keys to access APIs](https://cloud.google.com/docs/authentication/api-keys-use), extract `.sources/api-keys-use.md`)

Conflict: the method page lists only OAuth `cloud-platform` and IAM `recaptchaenterprise.assessments.create`. It does not mention API keys. ([Method: projects.assessments.create](https://cloud.google.com/recaptcha/docs/reference/rest/v1/projects.assessments/create), extract `.sources/rest-projects-assessments-create.md`) The authentication page (newer) states this method supports API keys. Follow the authentication page plus the create-assessment sample for API-key support. The header is the Cloud-wide equivalent of `key`; the reCAPTCHA sample only demonstrates `?key=`.

## Request JSON

The request body is an Assessment. ([Method: projects.assessments.create](https://cloud.google.com/recaptcha/docs/reference/rest/v1/projects.assessments/create), extract `.sources/rest-projects-assessments-create.md`)

Field names (REST JSON, all optional except Universal-key `expectedAction`):

| JSON path | Type | Official status |
| --- | --- | --- |
| `event.token` | string | Optional. User response token. |
| `event.siteKey` | string | Optional. Site key that generated the token. |
| `event.userIpAddress` | string | Optional. User device IP. Recommended in the website guide. |
| `event.expectedAction` | string | Optional. Same action as at token generation. Required for Universal keys. |

([REST Resource: projects.assessments](https://cloud.google.com/recaptcha/docs/reference/rest/v1/projects.assessments), extract `.sources/rest-projects-assessments.md`; [Create assessments for websites](https://cloud.google.com/recaptcha/docs/create-assessment-website), extract `.sources/create-assessment-website.md`)

## Response JSON

If successful, the body is an Assessment. ([Method: projects.assessments.create](https://cloud.google.com/recaptcha/docs/reference/rest/v1/projects.assessments/create), extract `.sources/rest-projects-assessments-create.md`)

| JSON path | Type | Range / notes |
| --- | --- | --- |
| `tokenProperties.valid` | boolean | Whether the token is valid. |
| `tokenProperties.action` | string | Action name provided at token generation. |
| `tokenProperties.invalidReason` | enum | Set when `valid` is false. |
| `riskAnalysis.score` | JSON `number` | 0.0–1.0. 1.0 likely legitimate; 0.0 likely not. Proto type is `float`. |

([REST Resource: projects.assessments](https://cloud.google.com/recaptcha/docs/reference/rest/v1/projects.assessments), extract `.sources/rest-projects-assessments.md`; proto type [Package google.cloud.recaptchaenterprise.v1](https://cloud.google.com/recaptcha/docs/reference/rpc/google.cloud.recaptchaenterprise.v1), extract `.sources/rpc-recaptchaenterprise-v1.md`; score meaning [Interpret assessments for websites](https://cloud.google.com/recaptcha/docs/interpret-assessment-website), extract `.sources/interpret-assessment-website.md`)

Conflict: the interpret sample writes `"score":"SCORE"` as a quoted placeholder. The REST schema owns the type: JSON `number`.

## HTTP status split

**Invalid token.** `valid = false` is a field on the Assessment (`invalidReason` may be `MALFORMED`, `EXPIRED`, `DUPE`, `MISSING`, and others). The interpret page treats that JSON as the assessment you receive after submit. Language samples check `valid` after CreateAssessment returns. ([REST Resource: projects.assessments](https://cloud.google.com/recaptcha/docs/reference/rest/v1/projects.assessments), extract `.sources/rest-projects-assessments.md`; [Interpret assessments for websites](https://cloud.google.com/recaptcha/docs/interpret-assessment-website), extract `.sources/interpret-assessment-website.md`; [Create assessments for websites](https://cloud.google.com/recaptcha/docs/create-assessment-website), extract `.sources/create-assessment-website.md`)

The owner pages do not print the digits `200`. The method page says a successful call returns an Assessment. Combined with `valid` living on that Assessment: an invalid token is still a successful create, not an HTTP error. authority: inference from those three official pages.

**Invalid API key.** No fetched reCAPTCHA owner page states the HTTP status. Do not invent it.

**Project / key mismatch.** Two different facts:

- Token-generating site key ≠ `event.siteKey` → Assessment with `tokenProperties.valid = false` and `invalidReason = KEY_MISMATCH` (or interpret: `siteKey` mismatch). ([REST Resource: projects.assessments](https://cloud.google.com/recaptcha/docs/reference/rest/v1/projects.assessments), extract `.sources/rest-projects-assessments.md`; [Interpret assessments for websites](https://cloud.google.com/recaptcha/docs/interpret-assessment-website), extract `.sources/interpret-assessment-website.md`)
- API key not associated with the project in the URL: the create-assessment page says use the key for the current project. It does not state the HTTP status if they differ. ([Create assessments for websites](https://cloud.google.com/recaptcha/docs/create-assessment-website), extract `.sources/create-assessment-website.md`)

## Action string matching

You must verify `tokenProperties.action` matches `event.expectedAction`. ([Interpret assessments for websites](https://cloud.google.com/recaptcha/docs/interpret-assessment-website), extract `.sources/interpret-assessment-website.md`)

Action names are not case-sensitive. Allowed characters: alphanumeric, slashes, underscores. ([Action names](https://cloud.google.com/recaptcha/docs/actions-website), extract `.sources/actions-website.md`)

API-enforced mismatch (`UNEXPECTED_ACTION` on `invalidReason`) is case-insensitive and only for `POLICY_BASED_CHALLENGE` keys when a non-empty `expectedAction` was sent and an action score threshold is higher than 0.0. Checkbox and score keys are not in that list; the application still compares the two strings. ([REST Resource: projects.assessments](https://cloud.google.com/recaptcha/docs/reference/rest/v1/projects.assessments), extract `.sources/rest-projects-assessments.md`)

Empty vs omitted `expectedAction`: the field is optional (required only for Universal keys). `UNEXPECTED_ACTION` requires a **non-empty** `expectedAction`. Official pages do not say whether an empty string is treated as omitted for checkbox/score keys. ([REST Resource: projects.assessments](https://cloud.google.com/recaptcha/docs/reference/rest/v1/projects.assessments), extract `.sources/rest-projects-assessments.md`)

## Sources

- Official: [Create assessments for websites](https://cloud.google.com/recaptcha/docs/create-assessment-website)
- Official: [REST Resource: projects.assessments](https://cloud.google.com/recaptcha/docs/reference/rest/v1/projects.assessments)
- Official: [Method: projects.assessments.create](https://cloud.google.com/recaptcha/docs/reference/rest/v1/projects.assessments/create)
- Official: [Authenticate to Fraud Defense](https://cloud.google.com/recaptcha/docs/authentication)
- Official: [Use API keys to access APIs](https://cloud.google.com/docs/authentication/api-keys-use)
- Official: [System parameters](https://cloud.google.com/apis/docs/system-parameters)
- Official: [Interpret assessments for websites](https://cloud.google.com/recaptcha/docs/interpret-assessment-website)
- Official: [Action names](https://cloud.google.com/recaptcha/docs/actions-website)
- Official: [Package google.cloud.recaptchaenterprise.v1](https://cloud.google.com/recaptcha/docs/reference/rpc/google.cloud.recaptchaenterprise.v1)
- Extracts: `.sources/`

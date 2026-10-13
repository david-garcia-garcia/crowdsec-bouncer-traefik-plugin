# Test coverage

1. [hard] Edge case untested — `pkg/httprule/action.go:329` — `bypass` sets both skips and `[captcha, bypass]` is the named both-legs-then-captcha path; no request test fails if either is reverted
   Fix: Assert `ActionBypass` zips both skips, and a `[captcha, bypass]` match captchas with `plugin:rules:<name>` while LAPI and AppSec stay idle
   Status: done
   Argument: added TestNewActionSet_bypassTokenSkipsBothLegs and TestServeHTTP_captchaPlusBypassSkipsBothThenCaptchas
   Quote:
      ```
      case ActionBypass:
      	parsed.skipLapi = true
      	parsed.skipAppsec = true
      ```
2. [hard] Critical path untested — `pkg/bouncer/bouncer.go:761` — AppSec `ban` over a captcha rule keeps origin `appsec` and WARNs; no test fails on revert
   Fix: Assert `[captcha, bypassLapi]` plus AppSec `action: ban` is the ban page, origin `appsec`, and `ServeHTTP:forcedCaptchaSuperseded`
   Status: done
   Argument: added TestServeHTTP_captchaPlusBypassLapiStillAllowsAppsecBan
   Quote:
      ```
      case appsec.ActionBan:
      	b.warnCaptchaSuperseded(req, match)
      	b.handleBanServeHTTP(rw, req, configuration.ReasonAPPSEC, headerReasonAppsec, "appsec")
      ```
3. [hard] Edge case untested — `pkg/bouncer/bouncer.go:771` — non-empty AppSec `challenge` must not relay when a captcha rule matched; no test hits that return
   Fix: Assert AppSec `action: challenge` with a body yields the plugin captcha page and origin `plugin:rules:<name>`
   Status: done
   Argument: added TestServeHTTP_nonEmptyAppsecChallengeDoesNotOverrideCaptchaRule
   Quote:
      ```
      if match.captchaName != "" {
      	return false
      }
      ```
4. [hard] Edge case untested — `pkg/bouncer/bouncer.go:350` — first matching ban name wins; no test fails if a later ban name is used
   Fix: Assert two matching `ban` rows emit `plugin:rules:` of the first name
   Status: done
   Argument: added TestServeHTTP_firstMatchingBanNameWins
   Quote:
      ```
      if match.banName == "" {
      	match.banName = b.actionRules.Name(i)
      }
      ```

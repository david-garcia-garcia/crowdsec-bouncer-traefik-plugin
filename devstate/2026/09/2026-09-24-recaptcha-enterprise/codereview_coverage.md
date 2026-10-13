# Test coverage

1. [hard] Edge case untested — `captcha.html:297` — stock `DrawCheckbox` vs hidden field and `BootScript`; reverting the html hunk stays green
   Quote:
      ```
      {{ if .DrawCheckbox }}
      <div id="captcha" class="{{ .FrontendKey }}" ... data-action="{{ .Action }}">
      {{ else }}
      <input type="hidden" name="g-recaptcha-response" id="g-recaptcha-response">
      {{ end }}
      <script>{{ .BootScript }}</script>
      Test: pkg/captcha/zzz_assessments_test.go enterpriseChallengePage fixture only; (none) executes stock captcha.html
      ```
   Fix: ServeHTTP GET on the stock template for checkbox and score; assert the checkbox div versus the hidden field and that score includes the boot script
   Status: done
   Argument: added Test_ServeHTTP_stockTemplateCheckboxAndScore.
2. [hard] Edge case untested — `pkg/captcha/assessments.go:129` — nil `riskAnalysis` with a configured minimum is treated as score 0 and must reject; no test hits that arm
   Quote:
      ```
      if v.minScore > 0 {
          score := 0.0
          if risk != nil {
              score = risk.Score
          }
          if score < v.minScore {
              return false
          }
      }
      Test: Test_Validate_assessmentsPassOrder "score below minimum rejects" sends riskAnalysis.score 0.3; (none) for missing riskAnalysis
      ```
   Fix: Assert valid+action with minScore set and no riskAnalysis is Reject
   Status: done
   Argument: added missing riskAnalysis with minScore rejects case.
3. [judgement] Happy path only — `pkg/captcha/widget.go:55` — score boot interpolates site key and action; test only asserts `ready` and `execute` substrings
   Quote:
      ```
      return "grecaptcha.enterprise.ready(function(){grecaptcha.enterprise.execute(" +
          quotedSiteKey + ",{action:" + quotedAction +
          "}).then(function(token){...
      Test: Test_New_enterpriseCheckboxAndScoreWidgets contains ready and execute only
      ```
   Fix: Assert the score BootScript includes the quoted site key and action
   Status: skipped
   Argument: judgement.
4. [judgement] Edge case untested — `pkg/configuration/configuration.go:747` — project id, action, and min score are required after trim; tests use empty string, not whitespace
   Quote:
      ```
      if strings.TrimSpace(config.CaptchaEnterpriseProjectID) == "" {
      action := strings.TrimSpace(config.CaptchaEnterpriseAction)
      minScore := strings.TrimSpace(config.CaptchaEnterpriseMinScore)
      Test: TestValidateParams_RecaptchaEnterprise missing-project / missing-action / missing-min-score cases set ""
      ```
   Fix: Assert whitespace-only project id, score action, and min score fail ValidateParams
   Status: skipped
   Argument: judgement.

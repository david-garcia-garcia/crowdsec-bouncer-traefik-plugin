# Deviations

- [x] taken  Go identifiers use house ID/API/IP stems
  Asked: Config and construction fields spelled `CaptchaEnterpriseProjectId`, `CaptchaEnterpriseApiKey`, `ApiKey`, `ProjectId`.
  Instead: `CaptchaEnterpriseProjectID`, `CaptchaEnterpriseAPIKey`, `APIKey`, `ProjectID` (JSON tags stay `captchaEnterpriseProjectId` / `captchaEnterpriseApiKey`).
  Owner: `pkg/configuration/configuration.go` (`LapiCapiMachineID`, `CaptchaGateBindIP`, `CaptchaCustomJsURL`)
  Why: honouring the task's Go spelling adds a second initialism style on the same Config surface.
  By: implement
  Requester: not asked

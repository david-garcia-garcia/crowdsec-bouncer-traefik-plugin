# Deviations

- [x] taken  slog `component` `CrowdsecBouncer` instead of ticket example `CrowdsecBounder`
  Asked: rename `component=CrowdsecBouncerTraefikPlugin` to something shorter like CrowdsecBounder.
  Instead: `CrowdsecBouncer`, the existing type and HTML template name in `pkg/bouncer/bouncer.go`.
  Owner: `pkg/logger/logger.go`
  Why: honouring the typed example would add a misspelled third identity next to the unit already named CrowdsecBouncer; the job is a shorter component, and that name already exists.
  By: explore
  Requester: not asked

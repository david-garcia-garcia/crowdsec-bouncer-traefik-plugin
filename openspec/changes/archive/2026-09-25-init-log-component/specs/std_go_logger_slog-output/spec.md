## ADDED Requirements

### Requirement: slog component is CrowdsecBouncer
Every logger constructed via `NewWithFormat` SHALL include attribute `component` equal to `CrowdsecBouncer`. JSON and common formats SHALL both carry that value. The value MUST NOT be `CrowdsecBouncerTraefikPlugin`.

#### Scenario: JSON logger component
- **WHEN** `NewWithFormat` is called with format `"json"`
- **THEN** a log record includes attribute `component` equal to `CrowdsecBouncer`

#### Scenario: Common logger component
- **WHEN** `NewWithFormat` is called with format `"common"`
- **THEN** a log record includes `component=CrowdsecBouncer`

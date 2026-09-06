## Purpose

Tumbling-window failure Tracker that trips a backend unhealthy after a threshold of failures in a window and auto-recovers after a backoff timeout so callers can skip outbound HTTP.

## Requirements

### Requirement: Tracker trips after threshold failures in a tumbling window
A Tracker SHALL count recorded failures. When the failure window is greater than zero, the count SHALL reset if that window has elapsed since the last reset (tumbling window). When the count reaches the configured threshold, the Tracker SHALL become unhealthy until the backoff timeout elapses. A threshold less than zero SHALL never trip. A backoff timeout of zero SHALL never skip (the Tracker SHALL stay healthy). A window of zero SHALL never reset the count except on auto-recover.

#### Scenario: Threshold trips
- **WHEN** the threshold is 5, the window is 30 seconds, and 5 failures are recorded inside that window
- **THEN** the Tracker is unhealthy

#### Scenario: Negative threshold never trips
- **WHEN** the threshold is -1 and many failures are recorded
- **THEN** the Tracker stays healthy

#### Scenario: Zero timeout never skips
- **WHEN** the backoff timeout is 0 and the threshold is reached
- **THEN** the Tracker does not skip outbound calls (stays healthy)

### Requirement: Unhealthy auto-recovers after backoff timeout
While unhealthy, `IsUnhealthy` SHALL stay true until the backoff timeout has elapsed. After that, the Tracker SHALL become healthy, reset the failure count, and the next outbound call is the probe. Success SHALL NOT decrement the failure count.

#### Scenario: Backoff expires
- **WHEN** the Tracker tripped and the backoff timeout has elapsed
- **THEN** the Tracker is healthy again
- **AND** the failure count is 0

#### Scenario: Window elapsed resets count before trip
- **WHEN** the window is 30 seconds, the threshold is 5, 4 failures are recorded, then more than 30 seconds pass, then 1 failure is recorded
- **THEN** the Tracker stays healthy

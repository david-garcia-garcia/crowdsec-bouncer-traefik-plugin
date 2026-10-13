## ADDED Requirements

### Requirement: Captured slog output is read through a mutex-guarded sink

An in-repo Go test that installs a `slog` handler in order to assert on the output SHALL write that output into a sink whose `Write` and whose read accessor are guarded by the same mutex, and SHALL read the captured text through that accessor. Such a test MUST NOT pass `*bytes.Buffer` directly to a `slog` handler and MUST NOT call `bytes.Buffer.String()` on a buffer a handler writes to. One sink helper SHALL serve the whole package; a per-test mutex beside a per-test buffer does not satisfy this requirement.

#### Scenario: Test captures output of code that logs from its own goroutine

- **WHEN** a test installs a `slog` handler and the code under test logs from a goroutine the test cannot join
- **THEN** the handler's writer serializes that write against the test's read under one mutex
- **AND** `go test -race` reports no data race on the captured output

#### Scenario: Test builds a capture logger

- **WHEN** a test needs a logger whose output it will assert on
- **THEN** it obtains the logger and the sink from the package's sink helper rather than declaring a `bytes.Buffer`

### Requirement: A test stops the component it started before reading its log

An in-repo Go test that starts a component which owns background tickers or goroutines SHALL stop that component before it reads captured log output. The stop SHALL happen inside the test body, not only through test cleanup, so no ticker of that component outlives the assertion.

#### Scenario: Test opens a client with background tickers

- **WHEN** a test constructs a component that starts a ticker, and later asserts on captured log output
- **THEN** the test stops that component before the read
- **AND** no ticker of that component is still running when the test function returns

#### Scenario: Existing assertions are preserved

- **WHEN** stopping the component earlier changes when a value can be observed
- **THEN** the test keeps asserting the same subject, ordered around the stop, rather than dropping the assertion

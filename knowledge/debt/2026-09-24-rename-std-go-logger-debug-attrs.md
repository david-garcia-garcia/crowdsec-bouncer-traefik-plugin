# Rename `std_go_logger_debug-attrs` to a Trace-named leaf

IssueKey: 2026-09-24-remediation-match-trace
Size: large
Action: note

## Why this follow-up

The live spec folder and usage packet are `std_go_logger_debug-attrs`, but the unit is Request-path Trace (`logger.Trace`, `slog.Level(-8)`). The fourth part still says Debug from the old hot-path Debug work.

## Why it was not taken

Archive history, the live catalog id, and the usage packet already use that leaf. Unattended take is only small rows on files this run created. This change still folds the remediating TRACE scenario onto the existing id.

## Risks

Later Trace work keeps landing on a Debug-named leaf. Reviewers search `debug-attrs` and miss TRACE breadcrumbs.

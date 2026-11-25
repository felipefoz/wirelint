# Automatic error handling warning default

- Status: Accepted
- Date: 2026-11-25
- Supersedes: the default-severity policy in
  [decision 0017](0017-auto-error-handling-rule.md)

## Context

The `auto-error-handling` rule detects a saved VI setting that teams may want
to review, but treating it as an error by default prevents scans from passing
the default error threshold. Users can still choose stricter enforcement
through per-rule severity configuration or a warning-level scan threshold.

## Decision

Keep the rule enabled by default, but change its default severity from `error`
to `warning`. Leave explicit severity configuration and the finding itself
unchanged.

## Alternatives and consequences

- **Keep error as the default:** rejected because the setting should be visible
  without making it a default CI blocker.
- **Disable the rule by default:** rejected because users should continue to
  see the saved setting in scan results.

The rule reports automatic error handling as a warning by default and can be
promoted to `error` in YAML when a project requires enforcement.

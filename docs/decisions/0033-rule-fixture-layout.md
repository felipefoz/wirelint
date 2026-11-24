# Rule fixture layout

- Status: Accepted
- Date: 2026-11-24

## Context

Rule examples were collected in shared fixture folders, making it difficult to
identify which files exercise each quality or security rule. Some fixtures are
also used by integration tests to check parser behavior rather than a rule.

## Decision

Keep rule fixtures in `tests/fixtures/quality/<rule-id>/` and
`tests/fixtures/sast/<rule-id>/`. Include any configuration needed to exercise
a rule. Keep non-rule regression fixtures under `tests/fixtures/quality/support/`.
Fixtures can intentionally produce findings, and both commands should scan the
entire fixture tree with `--fail-on none` while still reporting analysis errors.
New rules require representative fixtures alongside focused tests.

The saved-version examples include a LabVIEW-saved VI and a minimal synthetic
XML library with old version metadata. Their configuration exercises both
version bounds. The connector-pane-pattern fixture
requires its `checks.yaml` because that rule is inert without allowed patterns.

## Alternatives

- **A single examples folder:** obscures which rules have representative files.
- **Only generated unit-test data:** does not provide a persistent corpus for
  exercising the commands manually.

## Consequences

Rule-specific examples are easy to find and can be scanned independently.
Files may be duplicated when the same example usefully exercises different
rules. Existing automated tests may continue to use fixture files.

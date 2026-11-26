# Continuous integration

- Status: Accepted
- Date: 2026-11-16

## Context

WireLint supports Windows and Linux. Changes should be checked on both platforms before they are merged.

## Decision

Use GitHub Actions on pushes and pull requests. Run formatting checks, tests, and Clippy on standard GitHub-hosted Linux and Windows runners.

Configure security scanning through GitHub repository settings instead of a
dedicated security workflow. This replaces the previously configured CodeQL and
`cargo-audit` workflow.

## Consequences

- Keep the workflow checks aligned with the commands in `CONTRIBUTING.md`.
- Maintain coverage for both supported operating systems.
- Security scanning depends on the features enabled in GitHub settings; the
  removed workflow's schedule, manual trigger, and dependency audit no longer run.
- Keep tests self-contained in clean checkouts. Generate synthetic binary
  fixtures from tracked Rust test helpers instead of relying on ignored
  sandbox files, which are absent from CI.

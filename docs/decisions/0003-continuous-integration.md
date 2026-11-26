# Continuous integration

- Status: Accepted
- Date: 2026-11-16

## Context

WireLint supports Windows and Linux. Changes should be checked on both platforms before they are merged.

## Decision

Use GitHub Actions on pushes and pull requests. Run formatting checks, tests, and Clippy on standard GitHub-hosted Linux and Windows runners.

Run CodeQL for Rust and audit the lockfile against RustSec advisories in a
separate security workflow on pushes to `main`, pull requests, daily at 04:32
UTC, and on manual request. Use a manual Cargo build for CodeQL and
`cargo-audit` directly rather than automatically opening issues for advisories.

## Consequences

- Keep the workflow checks aligned with the commands in `CONTRIBUTING.md`.
- Maintain coverage for both supported operating systems.
- Security scans run on Linux and require GitHub code scanning to be enabled.
- Manual runs are available from the GitHub Actions Security workflow after it
  exists on the default branch. Scheduled runs also use the default branch.
- Keep tests self-contained in clean checkouts. Generate synthetic binary
  fixtures from tracked Rust test helpers instead of relying on ignored
  sandbox files, which are absent from CI.

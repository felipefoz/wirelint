# Analysis command names

- Status: Accepted
- Date: 2026-11-26

## Context

The `scan` command runs quality rules, while `sast` runs security rules. Their
names do not make that distinction as clear as the command descriptions.

## Decision

Rename `scan` to `lint` and `sast` to `security`. Keep `sast` as a visible
alias for `security`, but do not retain `scan` as an alias. Rule listings and
terminal summaries use the primary command names even when an alias is used.
The rule registries, configuration, and report formats are unchanged. This
supersedes the command names in decisions 0004 and 0026.

## Alternatives

Retaining `scan` as an alias would avoid breaking existing quality scripts, but
would leave the less specific command name in use. Keeping `sast` as the
primary name would preserve the abbreviation at the expense of clarity.

## Consequences

Existing scripts using `scan` must switch to `lint`. Existing `sast` scripts
continue to work, but their terminal scan type and rule listings use `security`.
GitLab's `sast` report format and schema fields retain their existing names.

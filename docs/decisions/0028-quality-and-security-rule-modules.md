# Quality and security rule modules

- Status: Accepted
- Date: 2026-11-23

## Context

Decision 0026 separates quality and security rules into command-specific
registries, but places both registries and implementations in one module.
As security checks are added, their implementation should remain distinct
from quality and source-control hygiene checks.

## Decision

- Put quality rules and their registry in `rules::quality`, and security
  rules and their registry in `rules::sast`.
- Keep the rule contract, severity, analysis runner, findings, discovery,
  configuration, reports, and VI-format readers shared. Each command still
  supplies its own registry to the shared pipeline.
- Defer a separate security analysis engine until a security feature requires
  different execution or dataflow semantics.

This supersedes only decision 0026's placement of the registries next to one
another, not its separate commands or shared execution model.

## Alternatives

- **Keep all rules together:** requires unrelated rule categories to grow in
  the same module and makes security ownership less clear.
- **Duplicate the analysis pipeline now:** adds divergence and maintenance
  cost without an existing security-specific execution requirement.

## Consequences

New security rules belong in `rules::sast`; quality rules belong in
`rules::quality`. Shared behavior and command output are unchanged. Rule fact
selection remains in the shared runner and may need a separate design if
security analysis grows beyond the current per-file fact model.

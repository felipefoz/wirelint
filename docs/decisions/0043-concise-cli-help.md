# Concise CLI help

- Status: Accepted
- Date: 2026-11-26

## Context

The root help repeated operational details and advertised `wirelint rules`,
while the lint command's summary singled out scalar path usage. The user guide
already documents rule behavior and configuration.

## Decision

- Keep the root help description brief and focused on WireLint's purpose.
- Describe the lint subcommand at the quality-analysis level rather than
  naming a specific rule.
- Remove the `wirelint rules` subcommand; use the rule references and
  configuration template to document built-in rules.

This supersedes only the `wirelint rules` command choices in decisions 0006
and 0026. The lint and security registries and their analysis behavior remain
unchanged.

## Alternatives

- **Keep the rules command and shorten only its description:** retains a
  command that duplicates the documented rule references.
- **Keep rule-specific detail in the lint summary:** makes the command list
  emphasize one rule rather than describe the lint command generally.

## Consequences

The root help is shorter, and users find rule details in the user guide and
configuration template instead of a separate CLI listing. Detailed command
help and rule behavior are unchanged.

## References

- [CLI guide](../user-guide/cli.md)
- [Quality and hygiene rules](../user-guide/quality-rules.md)

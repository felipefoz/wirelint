# Command-scoped configuration

- Status: Accepted
- Date: 2026-11-26

## Context

Lint and security analysis use separate built-in rule registries, but each
command previously needed its own YAML file. This duplicated shared settings
such as the failure threshold and directory exclusions, and made it harder to
configure both commands together.

## Decision

- Use one YAML file for both commands, with shared settings at the root and
  rule overrides under `lint.rules` and `security.rules`.
- Validate every configured rule against the registry named by its section.
  A rule placed in the other category is a configuration error, even if the
  current command would not run that rule.
- Keep the schema version at `1`; the new grouping does not introduce a new
  version.
- Continue accepting legacy top-level `rules` files as single-command
  configurations. Do not allow legacy top-level `rules` alongside populated
  category sections.
- Keep one combined example template listing all built-in rules and remove the
  separate security-only template.

This supersedes only decision 0026's separate-file configuration choice; the
separate commands and rule registries remain unchanged.

## Alternatives

- **Keep separate command-specific files:** duplicates shared settings and
  prevents a single configuration from expressing both rule sets.
- **Merge both registries into a shared `rules` map:** loses category
  separation and can let a security check be mistaken for a lint check.
- **Bump the schema version:** unnecessary because the configuration can
  preserve version-1 settings while adding explicit category sections.

## Consequences

Both commands accept the same `--config` file, but each runs only its own
registry and reads only its section's overrides. Misclassified rules fail
before scanning. Existing single-command configurations continue to work
without migration, while users can move their rule maps under the appropriate
category when combining configurations.

## References

- [CLI configuration and reports](0004-cli-configuration-and-reports.md)
- [Security analysis command and rules](0026-security-analysis-command-and-rules.md)

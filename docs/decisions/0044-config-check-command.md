# Configuration check command

- Status: Accepted
- Date: 2026-11-26

## Context

WireLint validates a configuration before scanning when `--config` is supplied
to `lint` or `security`. Users also need a way to validate edits without
starting analysis.

## Decision

- Add `wirelint config check <FILE>` to validate a YAML configuration without
  discovering or reading LabVIEW files.
- Validate both `lint.rules` and `security.rules`, even though no scan command
  is selected.
- Infer the category for legacy top-level `rules` files when all entries
  belong to one registry; reject mixed lint and security rules.
- Return status `0` and a short success message for valid files. Report
  invalid configuration through the normal error path and status `2`.

The `config` command group also contains initialization and display operations
as described in [decision 0045](0045-config-init-and-show.md).

## Alternatives

- **Use `wirelint validate-config <FILE>`:** direct, but leaves no command
  group for related configuration operations.
- **Add validation as a lint/security flag:** duplicates the operation across
  commands and would require choosing a rule registry.

## Consequences

Users can check the combined config before running a scan. Legacy
single-command configurations can also be checked without an extra category
argument; a legacy file mixing registries must be moved to the grouped schema.

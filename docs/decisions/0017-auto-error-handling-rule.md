# Automatic error handling rule

- Status: Accepted
- Date: 2026-11-18
- Partially superseded by: [decision 0035](0035-automatic-error-handling-vi-types.md)

## Context

Teams may require explicit error handling in VIs rather than LabVIEW's
automatic default error handling. The setting is stored in the LVSR save
record and can be checked using WireLint's existing bounded reader.

## Decision

Add the `auto-error-handling` rule for VI and VI-template RSRC resources
(`LVIN` and `sVIN`). Read bit 29 (`0x20000000`) of the LVSR `viFlags2` word at
payload offset 8, following pylavi's `AUTO_ERROR_HANDLING` interpretation.
Controls and XML containers do not supply this VI execution fact and are
skipped. The rule is enabled by default with error severity so a set flag
fails the default threshold.

The rule checks the saved setting only. It does not inspect block diagrams,
determine whether automatic handling is used at runtime, or modify files.

## Alternatives and consequences

- **Treat automatic handling as a warning:** warnings do not fail the default
  threshold, contrary to the intended policy that this setting fails the scan.
- **Apply the rule to controls or XML owner settings:** those values do not
  represent the execution setting of an individual VI.

Disabled settings pass. Findings identify the VI Properties > Execution
setting to disable. The shared rule enablement and severity overrides remain
available.

## References

- [Rule architecture](0006-rule-runner-and-source-only-check.md)
- [Format research and attribution](../../THIRD_PARTY_NOTICES.md)
- [pylavi LVSR flag definitions](https://github.com/marcpage/pylavi/blob/main/pylavi/resource_types.py)

# Automatic error handling on non-executable VI kinds

- Status: Accepted
- Date: 2026-11-24
- Partially supersedes: [decision 0017](0017-auto-error-handling-rule.md)

## Context

Global and polymorphic VIs can store the automatic error handling flag but
have no executable diagram of their own. Reporting that flag as an error
creates a finding that does not apply to their execution.

## Decision

Read the big-endian 16-bit `viType` field at LVSR payload offset 34. Return
no automatic-error-handling fact for Global (`4`) and Polymorph (`11`).
Keep the existing flag check for other VI kinds, including standard instances
of a polymorphic VI. Do not change other rules' applicability.

## Alternatives

- **Use the connector type descriptor:** adds type-pool parsing to this rule
  when the VI kind is already available in the required save record.
- **Ignore any VI without a diagram heap:** could hide findings in incomplete
  or unsupported files.

## Consequences

The rule no longer flags global or polymorphic VIs. It needs no additional
resources, dependencies, or LabVIEW installation at scan time. Existing
save-record validation and error reporting remain unchanged.

The genuine global and polymorphic fixtures have the saved flag clear.
LabVIEW rejected enabling it through VI Server with error 1035, so synthetic
reader tests exercise the enabled case without modifying genuine binaries.

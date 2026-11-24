# Connector panes on global and polymorphic VIs

- Status: Accepted
- Date: 2026-11-24
- Partially supersedes: [decision 0024](0024-connector-pane-pattern-rule.md)

## Context

The connector-pane rule requires a Function type descriptor when configured.
LabVIEW global and polymorphic VIs have no connector pane, and their `CONP`
descriptors use Cluster (`0x50`) and PolyVI (`0xF2`) types respectively. The
previous reader treated both as analysis errors.

## Decision

After validating and resolving `CONP` and `VCTP`, treat those two descriptor
types as having no connector pane. The rule does not report a finding for
them. Keep errors for missing or malformed metadata, unknown descriptor types,
and invalid Function patterns. Keep the unconfigured rule inert.

## Alternatives

- **Skip every non-Function type:** hides malformed or unsupported inputs.
- **Skip all connector data errors:** hides errors on ordinary VIs.

## Consequences

Configured scans can analyze global and polymorphic VIs without a false
analysis error. The two identified descriptor types are treated as pane-less
based on the descriptor kind; their contents are not otherwise validated by
this rule.

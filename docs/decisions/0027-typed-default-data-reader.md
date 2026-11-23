# Typed default-data reader

- Status: Accepted
- Date: 2026-11-23

## Context

Tier 1 SAST rules need facts from a VI's saved default values. In RSRC files,
those values are a sequential `DFDS` stream whose entries are selected and
ordered by the `TM80` type map. Correctly advancing through the stream
requires resolving types through `VCTP` and understanding each entry's
serialized shape. A string-only reader could silently associate bytes with
the wrong control when another type precedes it.

## Decision

- Add a bounded, read-only format reader that extracts string-valued defaults
  from VI-family RSRC files. Each value carries its type-map index, nested
  cluster/array field path, and original bytes; labels and secret matching
  remain consumer responsibilities.
- Resolve `TM80` entries through the `VCTP` top-level and flat Type Descriptor
  lists. Walk all default-data entries in order, including non-string values.
- Decode scalar numeric and Boolean values for stream advancement; recognize
  string, picture, and tag byte strings; recurse into clusters and arrays.
  CString/Pascal-string values are fixed-width numeric data, not text.
- Support the known special-cluster flags, including the version-dependent
  child selection for the flag-2 layout. Reject unsupported special flags,
  old `DSTM` maps, unsupported Type Descriptor kinds, malformed references,
  and resource layouts explicitly. Never guess a length or continue from an
  unknown offset.
- Apply a 64 MiB bound to decoded sections, a bound to collection counts and
  recursive nesting, and checked arithmetic to all offsets and sizes.
- Read defaults only when explicitly requested by an active analysis consumer.
  This change adds the parser substrate only; it does not add a SAST rule,
  decode the FP DCO table, inspect diagram constants, or parse CLFN nodes.

## Alternatives

- **Read only string entries:** rejected because preceding non-string values
  determine the offset of every later entry.
- **Decode all LabVIEW data types:** deferred; uncommon and version-specific
  types need separate format research. An explicit error is safer than an
  incorrect stream position.
- **Associate values with front-panel labels in this change:** deferred to a
  separate parser increment for the FP DCO table.
- **Use LabVIEW VI Scripting:** rejected by decisions 0001 and 0002; parsing
  must remain file-based, cross-platform, and independent of a LabVIEW
  installation.

## Consequences

Consumers can request typed string defaults and retain their raw bytes and
type-map locations without triggering this work for unrelated rules. Files
using unsupported layouts cannot produce these facts and report an explicit
analysis error when the reader is requested. The supported subset should grow
only with format evidence and focused fixtures.

## References

- [Format references and attribution](0001-project-identity-and-format-references.md)
- `pylabview/LVblock.py`: `DFDS`, `TM80`, and `VCTP`
- `pylabview/LVdatatype.py`: Type Descriptor layouts and type-map flags
- `pylabview/LVdatafill.py`: serialized default-value readers

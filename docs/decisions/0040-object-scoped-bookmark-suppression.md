# Object-scoped bookmark suppression

- Status: Accepted
- Date: 2026-11-25

## Context

The original bookmark reader retained only directive text. An arrowed ignore
therefore skipped an entire rule for the VI, hiding unrelated path values,
secret defaults/constants, or System Exec calls. Those rules aggregate multiple
source objects into a single finding, so filtering the finished message cannot
preserve unrelated violations.

## Decision

- Preserve unlinked diagram and XML directives as file-wide exceptions.
- Resolve a free label's `attachment` UID to an attachment object, then its
  `attachedObject` UID to the exempted source object. A floating attachment
  without `attachedObject` is not an arrow.
- Support object ignores for `path-usage`, `hardcoded-secret-default`, and
  `system-exec-command-input`. Other enabled rules reject linked directives.
- Qualify object identities by `BDHb` or `FPHb`. Normalize a value's display
  object to its owning DCO, a constant terminal to its child value DCO, and a
  diagram front-panel terminal through its
  saved DCO reference to the actual front-panel control.
- Linked pane free labels may supply object ignores; unlinked front-panel
  labels remain inert. Owned labels and subdiagram label parts are not directives.
- Resolve forward references after reading the whole bounded heap. Reject
  ambiguous identities, dangling links and cross-diagram arrows rather than
  widening an exception. Bound nesting to 256 scopes and identified objects
  to 100,000, alongside the existing 64 MiB decompression limit.
- Remove only the named rule's targeted values/calls before aggregation.
  Structures do not exempt descendants; inputs do not exempt downstream calls.
  A control exemption covers every string in that control's saved value.
- Retain the existing single finding per file/rule and CI report shape.
  Print applied object exceptions with their heap/UID; deduplicate them.
- Extract requested facts even for file-wide exceptions. Malformed metadata
  and incomplete command paths remain analysis errors regardless of ignores.

## Alternatives and consequences

Geometric proximity and matching names are unreliable after layout changes
and with duplicate names. Following dataflow or structure containment would
give an arrow broader scope than its saved target. Per-object reporting could
be added separately but is not required to preserve unsuppressed findings.

This extends source-heap validation to front panels when rules are enabled.
It deliberately changes file-wide System Exec and path ignores: they no longer
bypass requested extraction or hide its errors. Unknown/disabled rules still
produce no skip records. No new runtime dependencies are needed.

Tests use saved arrow fixtures and synthetic heaps for forward references,
floating attachments, namespace separation, malformed links and isolation.
Assertions check the remaining object and count, not just total findings.

## References

- [Original bookmark suppression](0019-bookmark-rule-suppression.md)
- [Format references and attribution](0001-project-identity-and-format-references.md)
- pylabview `LVheap.py`: `attachment` class 375, `attachedObject` field 618,
  and `attachment` field 619.
- labview-mcp `docs/diagram-layout.md`: saved comment-arrow UID chain.
- labview-mcp `docs/pylabview-comments.md`: floating attachment objects.

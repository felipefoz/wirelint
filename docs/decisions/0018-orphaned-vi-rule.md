# Orphaned VI rule

- Status: Accepted
- Date: 2026-11-18

## Context

A VI can retain an owning-library link after it has been removed from the
library's member list. Such a VI is linked to a library but is no longer
managed by that library, and the inconsistency is not visible from either file
in isolation.

## Decision

Add the `orphaned-vi` rule with error severity by default. Read the VI's
`VILB` owner link from the `LIvi` linker table and compare its relative
`PTH0` path with `.lvlib` files discovered in the same scan. A VI is orphaned
when the referenced library is scanned but its `Item Type="VI"` entries do not
list that VI. Nested library items are included.

Only relative owner links and member URLs that resolve within the scan root
are compared. Absolute/token paths and libraries not discovered in the scan
are outside this check, because WireLint has no reliable portable mapping for
system paths and cannot verify members of an unscanned file. Malformed
requested linker or member metadata is an analysis error, not a passing
result.

## Alternatives and consequences

- **Check only whether the owner library exists:** this misses the defining
  inconsistency, where the link is valid but the member list is stale.
- **Report links to libraries not present in the scan:** this would conflate
  external dependencies with orphaned members and produce false positives.
- **Treat missing or malformed metadata as a pass:** this could hide orphaned
  files; requested metadata errors instead fail analysis explicitly.

The rule requires a scan-wide relationship pass after each discovered file is
parsed. It does not modify VI or library files.

## Amendment (2026-11-24): resolve member URLs against the library file

LabVIEW library member URLs are relative to the library file itself, not its
directory: `../Member.vi` names a sibling VI. Resolve these URLs against the
library path before enforcing the scan-root boundary. The former
directory-relative interpretation produced false orphan findings for listed
members. Using the directory for URLs without `..` as a fallback would
misinterpret paths and could hide real orphans, so no fallback is used.

## Amendment (2026-11-24): resolve owner paths against the VI file

Relative `PTH0` owner paths start at the VI file, and each empty component
ascends one level. Preserve those components as `..` and resolve the path
against the VI file, subject to the existing scan-root boundary. Dropping
empty components and starting at the VI's directory could select a
same-named library in the wrong directory or skip a scanned owner.

## Amendment (2026-11-24): skip VI items without a URL

NI's LabVIEW 2024 `Function.lvlib` contains an `Untitled 8` VI item with no
`URL` attribute. This item has no saved file path and does not prevent LabVIEW
from using the library. Skip such items when collecting library members,
while preserving the library's other facts and all members with URLs.

Rejecting the entire library would make an unsaved-item placeholder an
analysis error. Guessing a path from the item name could incorrectly classify
an orphan as a member. Explicitly empty URLs remain analysis errors; other
member URL handling is unchanged. This exception only covers an absent attribute.

## References

- [Rule architecture](0006-rule-runner-and-source-only-check.md)
- [Format research and attribution](../../THIRD_PARTY_NOTICES.md)

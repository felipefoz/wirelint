# Bookmark and XML description rule suppression

- Status: Accepted
- Date: 2026-11-18

## Context

Some LabVIEW files need an explicit, local exception to a built-in rule.
LabVIEW bookmarks are free labels starting with `#` in the block diagram.
XML projects, libraries, and classes have native descriptions but no diagrams.

## Decision

Object-linked labels and extraction-error behavior are refined by
[decision 0040](0040-object-scoped-bookmark-suppression.md).

Read version-b block-diagram heaps from VI-family files and identify free
labels structurally, including nested diagrams. Interpret an exact
two-token `#wirelint-ignore RULE-ID` label as a per-VI suppression of that enabled
rule. For XML files, recognize the same two-token directive on standalone
lines in the owner's native description (`NI.Project.Description` for projects,
`NI.Lib.Description` for libraries/classes). Trim surrounding line whitespace;
ignore nested items and other properties. Report each skipped rule and file on
stdout in both verbosity modes.
Suppressions do not affect other files, findings, exit thresholds, or analysis
errors. Disabled and unknown rules do not produce skip records.

Bound decompression to 64 MiB and reject malformed or unsupported diagram
heaps explicitly. Do not treat text in owned labels, front panels, arbitrary
binary data, or other bookmarks as a directive. Binary files with no diagram
do not provide directives. Report formats continue to contain findings, not skips.

Read and validate XML owner descriptions whenever any rules are enabled, even
when `file-description` is disabled. Exclude directive lines from the non-empty
description check so directives alone cannot satisfy that rule. Prose and
directives may coexist; inline mentions in prose do not suppress rules.

Use `flate2` for zlib decompression rather than implementing a compression
format. Heap parsing is limited to the structure needed to identify label text.
Facts are still extracted before rule evaluation, so suppressions do not bypass
malformed metadata.

## Alternatives and consequences

Scanning raw bytes for the directive could incorrectly suppress rules based on
strings or front-panel text and would miss compressed diagrams. A configuration
file exclusion would not keep the exception with the VI. Structural parsing
keeps exceptions local, but extends analysis errors to malformed, oversized, or
unsupported diagrams even when other VI settings could be read. XML descriptions
keep exceptions editable in LabVIEW without inventing custom XML properties.
Malformed XML description properties now cause analysis errors even when the
description rule is disabled.

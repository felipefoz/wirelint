# Connector pane pattern rule

- Status: Accepted
- Date: 2026-11-20

## Context

A VI's connector pane assigns its inputs and outputs to one of LabVIEW's 36
fixed terminal layouts (for example "4x2x2x4", a 12-terminal layout), chosen
in the Icon/connector pane editor. Teams that enforce a house style for
subVI connector panes want to restrict which of these 36 layouts are
acceptable, and want the tool to say which layouts are allowed when a VI
does not comply.

No reference project named in
[format references](0001-project-identity-and-format-references.md)
documents a pattern-code-to-layout table directly. pylabview's `LVdatatype.py`
defines `TDObjectFunction`, the Type Descriptor kind (`TD_FULL_TYPE.Function`,
code `0xF0`) that describes a connector pane: a container of client Type
Descriptors (one per terminal) followed by an `fflags` word and a `pattern`
word, both read and written as opaque 16-bit integers with no documented
mapping to a named layout. pylabview's `LVblock.py` defines the `CONP`
(current) and `CPTM`/`CPCT`/`CPDI` (LabVIEW 7.1) blocks: `CONP` stores a
single big-endian 16-bit index into the VI's `VCTP` consolidated type pool,
identifying the VI's own `Function` Type Descriptor; its `modRSRC.py` resolves
that index through `VCTP`'s top-level list to the flat Type Descriptor it
names. None of pylabview's, pylavi's, or lvpm's files document what the raw
`pattern` value means.

labview-mcp's `docs/connector-pane-patterns.tsv` and
`docs/connector-pane-typecodes.tsv` close that gap. They were harvested from
a real LabVIEW installation (via VI Server sweeps and `pylabview`-based
extraction of ~400 `vi.lib` VIs) and record, for each of LabVIEW's 36
patterns: a terminal count, a published shape name (`catalogueShape`, matching
the LabVIEW Wiki's own documentation of these patterns), and, for 25 of the
36, the exact raw `pattern` value measured on a real VI using that layout.
Comparing those 25 measured pairs shows `pattern == ((catalog_id - 4800) * 8)
+ k`, with `k` a small low-order field (0-2 in the sample) whose meaning is
not established; dividing by 8 (an integer right shift by 3) recovers the
catalog offset exactly regardless of `k`, since the high bits are the pattern
ID "shifted three places" (the TSV's own description of the relationship).

Per [the AGENTS.md research workflow](../../AGENTS.md), these projects were
cloned into the untracked `.reference-repos/` folder and consulted there
(pylabview and labview-mcp on 2026-11-20); no implementation code was copied.

## Decision

Add the `connector-pane-pattern` built-in rule with warning severity,
applicable to VI and VI-template files (`.vi`, `.vit`, `.vim`); controls have
no connector pane and are skipped. The rule requires a nonempty
`allowed-patterns` list of pattern names (for example `"4x2x2x4"`); a VI is
reported only when its pattern's name is not in that list, and the finding
message repeats the configured allowed set so the user knows what is
accepted. Without a configured `allowed-patterns` list the rule is inert (no
finding, and the VI's connector pane data is not even read), since an
allow-list rule has no sensible default allow-list; WireLint does not guess
one. Pattern names are validated against WireLint's own copy of the 36-entry
name/terminal-count table (sourced from labview-mcp's `catalogueShape`
column) at configuration time, rejecting typos immediately.

Read the pattern as follows:

1. Locate the VI's `CONP` block (not `CPC2`: `CONP`'s type is created
   unconditionally for every VI, while `CPC2` is only created once the
   connector pane is first edited away from its default, per pylabview's
   comments). Read its single 16-bit big-endian type index.
2. Locate the VI's `VCTP` block (always zlib-coded, like the existing
   `BDHb` block-diagram heap reader). Decode it with the same `ZlibDecoder`
   approach and the same 64 MiB size bound as `BDHb`, in a separate reader
   since `VCTP`'s decompressed layout (flat Type Descriptor list, then a
   top-level index list) differs from a diagram heap's. Parse the flat
   list (recording each entry's start offset, skipping entries other than
   the one needed) and the top-level index list.
3. Resolve the `CONP` index through the top-level list to a flat Type
   Descriptor offset, requiring that entry's type to be `Function`
   (`0xF0`); read past its client list and `fflags` word to its `pattern`
   word.
4. Divide `pattern` by 8 (right shift by 3) to get a catalog offset; reject
   offsets outside 0-35 rather than guessing a layout for an unrecognized
   code.

Missing or malformed `CONP`/`VCTP` data, a non-`Function` Type Descriptor at
the resolved offset, and out-of-range indices or pattern codes are all
analysis errors, and only when `allowed-patterns` is configured (mirroring
`password-set`'s and `file-description`'s "error only when the rule can
actually use the fact" behavior) — never a guessed or defaulted pattern.

## Alternatives and consequences

- **Enforce a single required pattern, or only a terminal-count bound:**
  rejected in favor of an explicit allow-list of named patterns, which
  matches how LabVIEW presents a closed set of patterns to choose from (not
  a count or shape to compute) and directly supports the ask to "list what
  options are allowed."
- **Always read the connector pane for every scanned VI:** rejected because
  the rule cannot report anything useful without a configured
  `allowed-patterns` list; always requiring valid `CONP`/`VCTP` data would
  turn an inert, unconfigured rule into a source of spurious analysis
  errors on otherwise-unrelated files.
- **Support `CPC2` instead of, or in addition to, `CONP`:** deferred. Per
  pylabview's comments, `CONP`'s type is created with every new VI, so it is
  the reliable source; `CPC2` exists only after the pane is first edited and
  was not needed to read the pattern.
- **Name patterns by terminal count alone (e.g. "12 terminals"):** rejected
  because several patterns share a terminal count (for example both
  `3x2x2` and `4x2x3` have 9 terminals) but differ in shape; the
  `catalogueShape` name disambiguates them and matches external
  documentation.

## References

- [Rule architecture](0006-rule-runner-and-source-only-check.md)
- [Format research and attribution](../../THIRD_PARTY_NOTICES.md)
- [Quality and hygiene rule guide](../user-guide/quality-rules.md)
- [Terminal style rule](0022-terminal-style-rule.md) (precedent for bounded,
  zlib-coded block parsing and for VI-family-only applicability)

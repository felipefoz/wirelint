# Terminal display style rule

- Status: Accepted
- Date: 2026-11-20

## Context

A front-panel control or indicator's terminal on the block diagram can be
displayed either as an icon (resembling the control) or as a compact
data-type glyph, toggled per terminal with the **View As Icon** context-menu
item. Teams differ on which they prefer as a house style, but want every
terminal in a VI to agree with that choice.

No reference project named in
[format references](0001-project-identity-and-format-references.md)
documents the bit distinguishing these two styles. pylavi does not parse
front-panel or block-diagram objects at all. pylabview's `LVparts.py` defines
the right structural scaffold (an `OBJ_FLAGS` enum of 32 `OFFBit<N>` members
on front-panel/block-diagram parts) but marks every relevant bit, including
the one this rule needs, `# unknown`.

Because no existing description covered this bit, it was identified through
original experimentation rather than cited documentation: two pairs of
otherwise-minimal VIs (one numeric control; one string and one numeric
control) were saved with their terminals' **View As Icon** state toggled and
left unchanged, then compared using pylabview's `readRSRC.py -x` extractor
(a local research tool, not a WireLint dependency) to get semantic XML
instead of hand-parsing the heap bytecode. Across both pairs, the only
consistent difference on the `fPTerm` (terminal) object was a single bit,
`0x04000000` (bit 26) of its 32-bit `objFlags` field, set only when the
terminal displayed as an icon. This was corroborated by the terminal's
recorded bounding box: icon-style terminals measured a square matching the
control's icon size; data-type-style terminals measured a narrow box matching
a compact type glyph. The result held for both a numeric control and a string
control, ruling out a control-type-specific encoding.

## Decision

Add the `terminal-style` built-in rule with warning severity, applicable to
VI and VI-template files (`.vi`, `.vit`, `.vim`); controls have no block
diagram and are skipped. The rule requires every terminal to match one
configured preferred style, `preferred-style: data-type` or
`preferred-style: icon`, defaulting to `data-type`. A VI is reported only
when at least one terminal does not match the preferred style; a VI with
zero or one terminal always passes.

Read each terminal's style from the `fPTerm` object's `objFlags` field (bit
`0x04000000`) in the VI's compressed version-b block diagram heap (`BDHb`),
reusing the bounded heap walk already implemented in `src/formats/heap.rs`
for bookmark directives (same decompression, size limit, and tag/scope
parsing; extended to also recognize `fPTerm` terminal objects and their
`objFlags` field). The heap, tag, and class identifiers (`SL__fPTerm`,
`OF__objFlags`) are documented in pylabview's `LVheap.py`; only the bit's
*semantic meaning* was original research. See
[THIRD_PARTY_NOTICES.md](../../THIRD_PARTY_NOTICES.md) for the full
attribution and the exact method used.

VIs using the unsupported legacy (`BDHP`/`BDHc`) block diagram heap format
already fail analysis before any rule runs, per the existing bookmark-reader
behavior; this rule introduces no new format-support gap.

## Alternatives and consequences

- **Name it `mixed-terminal-style`:** this is NI VI Analyzer's name for a
  related test. WireLint is an independent project with a similar purpose
  to VI Analyzer, not a derivative, so it uses a different, equally
  descriptive ID, `terminal-style`, matching the naming pattern of other
  settings-style rules (`saved-version`, `debugging-status`).
- **Report inconsistency without a preferred style, instead of requiring a
  specific style:** an earlier version of this rule only flagged a VI that
  mixed both styles, taking no side on which style was correct. User
  feedback was that this undershot the actual need: teams want to enforce a
  house style, not merely forbid mixing two unspecified styles. The
  configurable `preferred-style` option, defaulting to `data-type`,
  supersedes that design.
- **Report every non-conforming terminal individually:** a single
  file-level finding is simpler, matches the style of other built-ins, and is
  sufficient to point a user at the VI to fix; per-terminal findings would
  need terminal names or positions, which are out of scope for this change.
- **Treat a VI with zero or one terminal as unsupported:** these trivially
  cannot have a mismatched terminal, so they simply produce no finding, like
  any other rule given facts that do not apply.

## References

- [Rule architecture](0006-rule-runner-and-source-only-check.md)
- [Format research and attribution](../../THIRD_PARTY_NOTICES.md)
- [Quality and hygiene rule guide](../user-guide/quality-rules.md)

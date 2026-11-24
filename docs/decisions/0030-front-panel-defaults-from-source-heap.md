# Front-panel default values from the source heap

- Status: Accepted
- Date: 2026-11-23

## Context

Decision 0027 read string defaults from the `DFDS` data space, selected by the
`TM80` type map. Running `wirelint sast` over LabVIEW 2024's `vi.lib` (33,052
files) showed that this cannot work on real VIs: all 29,282 VI-family files
failed analysis. 27,591 had no `DFDS` block at all, 1,049 stopped at an
unsupported Type Descriptor kind inside `DFDS`, and 642 had an unsupported
`TM80` section table.

Two probe VIs with known defaults, identical except for the "Separate
compiled code from source file" setting, explained why:

- `DFDS`, `TM80`, `VICD`, and related blocks exist only when compiled code is
  stored in the VI. They are compiled data, not source. A VI with separated
  compiled code, the usual setting for source control, has none of them.
- In both files, the front-panel heap `FPHb` stores each control's default as
  a `DefaultData` field on its `fPDCO` object, in LabVIEW's flattened form,
  next to a heap `typeDesc` TypeID. LabVIEW omits the field when the default
  is empty or zero.
- `DTHP` maps heap TypeIDs onto a slice of `VCTP`: TypeID `n` is top-level
  type `IndexShift + n - 1`. The Type Descriptor may carry a label, but some
  controls store their name only in their front-panel display object.
- `DFDS` is a single unkeyed stream that also holds internal data-space
  entries. One unsupported type stops every later value. `DefaultData` is
  length-delimited per control.

labview-mcp's pylabview findings (§3.16 to §3.19) reached the same
conclusion for block-diagram terminals: values live in `DefaultData` in the
heap, and wired diagram constants in `ConstValue`.

## Decision

- Read VI facts only from source blocks. Never use compiled-code blocks such
  as `DFDS`, `TM80`, or `VICD`: they are absent from source-only VIs and hold
  derived data when present.
- Read front-panel defaults from `FPHb`. Collect `typeDesc` and `DefaultData`
  only when they are direct fields of an `fPDCO` object (nested controls
  included), ignoring the same tags deeper in a control's parts. A
  `DefaultData` without a `typeDesc` is an analysis error.
- Read the control name from the direct `ddo` object's `partsList` name-label
  part (`partID` 16), excluding captions and labels on nested display objects.
  Prefer this name over the control's Type Descriptor label; retain descriptor
  labels for nested values and as a fallback when the control name is absent.
  A converted string constant in a real VI has a saved default and a front-panel
  name but an unlabeled control Type Descriptor, which exposed this gap.
- Reuse one heap tokenizer for `BDHb` and `FPHb`; parse errors name the heap.
  Older `FPHP`/`FPHc` heaps are an explicit analysis error when defaults are
  requested.
- Resolve each control through `DTHP` (`count`, then `IndexShift` when the
  count is nonzero) and `VCTP`. A TypeID outside the `DTHP` slice or the `VCTP`
  top-level list is an analysis error. `DTHP` is read only when at least one
  control stores a default.
- Decode each `DefaultData` on its own with the flattened-value walker from
  decision 0027, without type-map flags or alignment. A control whose value
  uses an unsupported type, is truncated, or has trailing bytes is skipped;
  other controls are still reported.
- Identify a value by its one-based `VCTP` top-level type index
  (`type_index`), replacing the `TM80` type-map index.
- Keep two real LabVIEW 2024 VIs, saved with separated and with embedded
  compiled code, as test fixtures under `tests/fixtures/sast/`, and mark
  VI-family files as binary in `.gitattributes`.

## Alternatives

- **Keep `DFDS` and add support for more types:** rejected. Source-only VIs
  have no `DFDS`, and embedded VIs would still fail on internal data-space
  entries unrelated to controls.
- **Read `DFDS` when present and `FPHb` otherwise:** rejected. It would
  analyze compiled data, give two code paths for one fact, and both blocks hold
  the same front-panel defaults.
- **Treat an undecodable control as a file analysis error:** rejected. Values
  are independent, so one unknown type should not hide credentials in other
  controls. Skipping can miss a string nested in an unsupported type.
- **Use the `vistrings` package or pylabview at runtime:** rejected by
  decisions 0001 and 0002; both are research references only.

## Consequences

`wirelint sast` now analyzes VIs in both save modes. On LabVIEW 2024's
`vi.lib` it analyzed all 33,052 files with no analysis errors, in 8.5 s with a
warm file cache. The first run after the files leave the cache is dominated
by disk reads and was several minutes on Windows. Values in types the walker
does not support are skipped silently. Decision 0031 extends the shared heap
tokenizer to read scalar block-diagram string constants from `BDHb`.

## References

- [Typed default-data reader](0027-typed-default-data-reader.md)
- [Hardcoded secret default rule](0029-hardcoded-secret-default-rule.md)
- `pylabview/LVheap.py`: `OF__DefaultData`, `OF__typeDesc`, `SL__fPDCO`, and
  `HeapNodeTypeId`, plus `OF__ddo`, `OF__partsList`, and `OF__partID`
- `pylabview/LVparts.py`: `PARTID.NAME_LABEL`
- `pylabview/LVblock.py`: `DTHP.getHeapTD` and `VCTP.getTopType`
- `labview-mcp/experiments/pylabview/FINDINGS.md`: §3.16 to §3.19

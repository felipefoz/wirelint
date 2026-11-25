# Third-party notices and format references

## LabVIEW RSRC format research

WireLint's original Rust RSRC reader was informed by the
[pylabview project](https://github.com/mefistotelis/pylabview), specifically:

- [`LVrsrcontainer.py`](https://github.com/mefistotelis/pylabview/blob/master/pylabview/LVrsrcontainer.py):
  format-3 RSRC headers, block-info tables, and resource file-type identifiers.
- [`LVblock.py`](https://github.com/mefistotelis/pylabview/blob/master/pylabview/LVblock.py):
  block/section offsets and the LVSR save-record layout.
- [`LVinstrument.py`](https://github.com/mefistotelis/pylabview/blob/master/pylabview/LVinstrument.py):
  the `viFlags2` word and `SourceOnly` bit 10, and the `instrState` word at
  LVSR offset 24 with `DebugCapable` bit 9.
- [`LVmisc.py`](https://github.com/mefistotelis/pylabview/blob/master/pylabview/LVmisc.py):
  LabVIEW version-word encoding and major/minor components.

These were consulted as descriptions of the file format, including a locally
vendored copy in labview-mcp, on 2026-11-17. No third-party implementation code,
substantial text, or binary fixtures are copied into WireLint. Its RSRC test
inputs include synthetic examples and project-created LabVIEW files. Existing
external LabVIEW fixtures were also checked read-only during development.

The VI description reader also uses pylabview's description of `STRG` resource
sections and LabVIEW string layouts in `LVblock.py` and `LVmisc.py`.

The debugging-status reader uses pylabview's `DebugCapable` definition.
[pylavi's `TypeLVSR`](https://github.com/marcpage/pylavi/blob/main/pylavi/resource_types.py)
and [validation logic](https://github.com/marcpage/pylavi/blob/main/pylavi/validate.py)
were also consulted on 2026-11-18. pylavi's debuggable mask additionally
includes instrument-state bit 30, which pylabview labels unknown. WireLint
uses only pylabview's documented bit 9. No implementation code was copied
from either project.

The `no-breakpoints` rule uses pylavi's `TypeLVSR.BREAKPOINTS_SET`
interpretation (word 5, mask `0x20000000`) from the same
[`resource_types.py`](https://github.com/marcpage/pylavi/blob/main/pylavi/resource_types.py)
reference. This is bit 29 of the instrument-state word, which pylabview leaves
unknown; WireLint follows pylavi's explicit breakpoint label rather than
deriving breakpoint presence from debugging capability. No implementation
code was copied.

pylavi's
[`TypeBDPW.has_password`](https://github.com/marcpage/pylavi/blob/main/pylavi/resource_types.py)
compares the first BDPW hash with the empty-password marker. WireLint uses
that documented interpretation to detect password presence without keeping
or exposing the hash. No implementation code was copied.

The `auto-error-handling` rule uses pylavi's
[`TypeLVSR.AUTO_ERROR_HANDLING`](https://github.com/marcpage/pylavi/blob/main/pylavi/resource_types.py)
interpretation (viFlags2 word 1, mask `0x20000000`), which identifies the
saved automatic error handling setting. No implementation code was copied.
Its applicability check uses pylabview's `LVinstrument.py` definitions of
`LVSRData.viType` (big-endian 16-bit field at offset 34), `VI_TYPE.Global`
(`4`), and `VI_TYPE.Polymorph` (`11`). labview-mcp's offline evaluation
reported that these non-executable VI kinds can carry the flag. These sources
were consulted as format descriptions; no implementation code was copied.

The `orphaned-vi` rule's linker-table and path-format research was informed by
pylabview's [`LVlinkinfo.py`](https://github.com/mefistotelis/pylabview/blob/master/pylabview/LVlinkinfo.py)
(`VILB`, VI-to-library links) and LVPM's
[`deptree.py`](https://github.com/labview-package-manager/lvpm/blob/master/tools/linkfix/deptree.py)
and [`linkobjs.py`](https://github.com/labview-package-manager/lvpm/blob/master/tools/linkfix/linkobjs.py)
(`LIvi` linker sections and bounded `PTH0` paths). These sources were
consulted as format descriptions; no implementation code was copied.
The library member URL interpretation was also checked against labview-mcp's
offline file reader and its saved-library fixtures. Those references were
consulted read-only; the test VI is a user-created sandbox VI.
The VI owner path's file-relative base and empty-component semantics were
checked against labview-mcp's offline file reader and its evaluation of saved
VIs. pylabview's `LVclasses.py` was consulted for the `PTH0` component format.
No implementation code was copied.

Block-diagram bookmark extraction was informed by pylabview's `HeapVerb` in
[`LVblock.py`](https://github.com/mefistotelis/pylabview/blob/master/pylabview/LVblock.py),
heap tags in [`LVheap.py`](https://github.com/mefistotelis/pylabview/blob/master/pylabview/LVheap.py),
and variable-width fields in `LVmisc.py`. The distinction between free labels
and owned labels was checked against
[lvkit](https://github.com/pragmatest-dev/lvkit)'s block-diagram parser. These were
used as format descriptions; no implementation code or fixtures were copied.

The `terminal-style` rule reuses that same `BDHb` heap reader,
extended to also recognize `fPTerm` terminal objects. The class and field
identifiers come from pylabview's `LVheap.py`: `SL_CLASS_TAGS.SL__fPTerm`
(value 22) and `OBJ_FIELD_TAGS.OF__objFlags` (value 172, a standard
variable-length integer field). Neither `LVheap.py` nor `LVparts.py`'s
`OBJ_FLAGS` enum documents which `objFlags` bit selects icon-style versus
data-type-style terminal display — `LVparts.py` lists it as
`OFFBit26 = 1 << 26  # unknown`. That bit's meaning was determined through
original experimentation on 2026-11-20: two pairs of minimal VIs (one
numeric control; one string and one numeric control) were saved with a
terminal's **View As Icon** state toggled, then compared using pylabview's
`readRSRC.py -x` extractor (used here only as a read-only research tool, not
vendored or added as a WireLint dependency). The only consistent difference
on the terminal's `objFlags` field was bit `0x04000000`, set for icon style
and clear for data-type style, corroborated by the terminal's recorded
bounding box (icon-sized square versus a narrow data-type glyph) across both
a numeric and a string control. No implementation code was copied; only
pylabview's tag/field numbering scheme was consulted, and the bit's meaning
is WireLint's own finding, not pylabview's.

pylabview attributes these source files to Mefistotelis and distributes them
under the MIT License. Refer to its
[license](https://github.com/mefistotelis/pylabview/blob/master/LICENSE).

The `connector-pane-pattern` rule's `CONP`-to-`VCTP`-to-`Function`-TypeDesc
chain was informed by pylabview's
[`LVblock.py`](https://github.com/mefistotelis/pylabview/blob/master/pylabview/LVblock.py)
(the `CONP` block's single type index, and the zlib-coded `VCTP`
consolidated type pool's flat Type Descriptor and top-level index lists) and
[`LVdatatype.py`](https://github.com/mefistotelis/pylabview/blob/master/pylabview/LVdatatype.py)
(`TD_FULL_TYPE.Function`, code `0xF0`, and `TDObjectFunction`'s `pattern`
field). None of these document what a `pattern` value means. That mapping —
which of LabVIEW's 36 named connector pane patterns (for example
"4x2x2x4") a given `pattern` value selects — came from
[labview-mcp](https://github.com/Zuehlke/labview-mcp)'s
`docs/connector-pane-patterns.tsv` and `docs/connector-pane-typecodes.tsv`,
harvested from a real LabVIEW installation via VI Server sweeps and
pylabview-based extraction of sampled `vi.lib` VIs. WireLint's own
36-entry name table (`CONNECTOR_PANE_PATTERNS` in `src/rules.rs`) reproduces
only the pattern names and terminal counts from those tables, not their
per-terminal slot geometry or sample VI names. labview-mcp distributes its
own code under the MIT License; refer to its
[license](https://github.com/Zuehlke/labview-mcp/blob/main/LICENSE). See
[decision 0024](decisions/0024-connector-pane-pattern-rule.md) for the full
reasoning, including how the raw `pattern` field maps to a pattern offset.
For pane-less VIs, labview-mcp's `docs/offline-audit-evaluation.md` and
`LvFileAudit.ConnectorPane` report `PolyVI` (`0xF2`) and `Cluster` (`0x50`)
descriptors for polymorphic and global VIs, respectively. pylabview's
`LVdatatype.py` defines those type codes. These were consulted as format
descriptions; no implementation code or external fixtures were copied.

The typed default-data reader uses pylabview's descriptions of `VCTP`,
`DTHP`, Type Descriptor references and labels, heap tags (`OF__DefaultData`,
`OF__typeDesc`, `SL__fPDCO`), and serialized DataFill values in `LVblock.py`,
`LVdatatype.py`, `LVheap.py`, and `LVdatafill.py`. labview-mcp's
`experiments/pylabview/FINDINGS.md` (§3.16 to §3.19) independently reported
that heap `DefaultData` holds terminal values. These are used as format
descriptions only; no implementation code or fixtures were copied. The
`FPHb` source for front-panel defaults was confirmed with WireLint's own probe
VIs. See [decision 0027](docs/decisions/0027-typed-default-data-reader.md) and
[decision 0030](docs/decisions/0030-front-panel-defaults-from-source-heap.md).
The front-panel name-label reader also uses pylabview's `OF__ddo`,
`OF__partsList`, and `OF__partID` tags in `LVheap.py` and
`PARTID.NAME_LABEL` in `LVparts.py` as format references.
The scalar diagram-string reader uses pylabview's `SL__bDConstDCO`,
`SL__stdString`, and `OF__ConstValue` in `LVheap.py`, and labview-mcp's
`experiments/pylabview/FINDINGS.md` section 3.19 as format references.

The structural diagram graph reader uses pylabview's UID/class attributes,
object class and field IDs, and signed heap integer representation in
`LVheap.py`. labview-mcp's `experiments/pylabview/FINDINGS.md` section 3 and
`experiments/aixml-without-grpc/FINDINGS.md` describe symbolic terminal
connections, fan-out and structure boundaries. These were consulted as format
descriptions. Tests use synthetic data and existing project-owned VIs;
no implementation code or external fixtures were copied.

## Rust dependencies

WireLint uses Clap for the CLI, flate2 for zlib decompression, roxmltree for
XML parsing, and Serde with serde_yaml_ng for typed YAML configuration. Each dependency retains its own
license; dependency versions and transitive dependencies are recorded in
`Cargo.lock`.

# Path usage rule

- Status: Accepted
- Date: 2026-11-25

## Context

Hardcoded absolute paths and invalid target-platform syntax reduce portability.
LabVIEW saves path values as flattened path records in source heaps. Dedicated
Empty Path and Not a Path constants are fixed nodes, distinct from ordinary
path constants even when their values match.

## Decision

- Add the enabled-by-default warning `path-usage` for scalar `stdPath` diagram
  constants and front-panel defaults. Warn for empty ordinary constants,
  absolute or UNC values, and relative components invalid on a selected target.
  Do not report the dedicated fixed nodes or the Not a Path value.
- Configure `targets` as a nonempty distinct list of `windows` and/or `linux`,
  both by default. Check syntax without accessing the filesystem or depending
  on the host. A path invalid on any selected target is reported.
- Read only source `BDHb` and `FPHb` heaps and decode `PTH0`, `PTH1`, and
  `PTH2` with bounded lengths. Malformed path records produce analysis errors.
  Report the first offending object and a count of other offending values.
- Keep saved-path decoding and extracted values generic in the format layer;
  apply portability policy in the `path-usage` rule.
- Initially inspect scalar objects only; array and cluster values and runtime
  path construction are not analyzed. Front-panel indicator defaults are
  included. The dedicated Not a Path node is covered by a synthetic heap test,
  not a LabVIEW-saved fixture.

## Alternatives

- Checking existence was rejected because it depends on the scan machine and
  deployment environment. Searching heap text was rejected because it cannot
  distinguish path values from unrelated strings.
- Platform-specific host APIs were rejected because the same VI should produce
  the same findings on Windows and Linux.

## References

- [Project identity and format references](0001-project-identity-and-format-references.md)
- [Windows and Linux compatibility](0002-windows-linux-compatibility.md)
- `pylabview/pylabview/LVclasses.py`: `LVPath0` and `LVPath1` records.
- `pylavi/pylavi/data_types.py`: `Path` record kinds.
- `labview-mcp/scripts/aixml-pylabview/aixml2vi.py`: flattened empty paths.
- `lvpm/tools/linkfix/deptree.py`: PTH0 path type and component records.

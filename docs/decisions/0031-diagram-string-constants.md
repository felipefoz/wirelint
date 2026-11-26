# Diagram string constants in security analysis

- Status: Accepted
- Date: 2026-11-24

## Context

The hardcoded-secret rule reads front-panel defaults but missed a string
constant labelled `password` on a VI's block diagram. The source `BDHb` heap
stores a constant's flattened value on its `bDConstDCO` object as `ConstValue`.
The object's `stdString` display object identifies a scalar string and owns
its name label. `ConstValue` contains a four-byte big-endian length and the
string bytes.

## Decision

- Read scalar string constants from `BDHb` only when the secret rule requests
  string facts. Reuse the heap walker and the owned name-label parser from
  front-panel defaults. Restrict values to direct `ConstValue` fields of
  `bDConstDCO` objects with direct `stdString` display objects, including
  objects in nested diagrams.
- Apply the existing credential-name, token, private-key, and assignment
  matchers to each constant. Keep the existing rule ID and one-finding-per-file
  behavior; identify a constant in the message without revealing its value.
- Treat missing, ambiguous, truncated, or trailing scalar string `ConstValue`
  data as an analysis error. Older VIs may not store a constant's value in
  the source heap; compiled blocks are not used as a fallback.
- Share flattened-string decoding between diagram constants, front-panel
  defaults and call-input analysis. Require complete consumption for scalar
  constants, while allowing following values in composite control defaults.

## Alternatives

- **Search all heap text:** rejected because labels, captions, and non-string
  constants are not necessarily saved constant values.
- **Decode composite constants:** deferred. Arrays and clusters require type
  resolution and traversal beyond scalar `stdString` objects.
- **Read compiled-code blocks for missing values:** rejected by decision 0030.

## Consequences

VIs with diagram source can report credentials in scalar string constants as
well as control defaults. Matching remains heuristic and does not trace
dataflow. Composite constant values are not inspected. A string constant
without a stored source value produces an analysis error instead of appearing
to pass.

## References

- [Front-panel defaults from the source heap](0030-front-panel-defaults-from-source-heap.md)
- `pylabview/LVheap.py`: `SL__bDConstDCO`, `SL__stdString`, `OF__ConstValue`
- `labview-mcp/experiments/pylabview/FINDINGS.md`: section 3.19

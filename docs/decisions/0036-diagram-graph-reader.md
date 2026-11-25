# Structural block-diagram graph reader

- Status: Accepted
- Date: 2026-11-25

## Context

The command-input investigation in decision 0026 confirmed that saved diagrams
contain terminal-UID connections and per-node identities. A dependency on
`System Exec.vi` alone is not a security finding. Following a control through
string operations requires a graph and, separately, validated transfer rules.

The existing heap walker discards UIDs and extracts only selected per-file
facts. Its callers must not pay to build a graph before an analysis needs one.

## Decision

- Add an opt-in `formats::read_diagram_graph` entry point for format-3 VI
  resources with a version-b `BDHb` source heap. Reuse the validated RSRC
  header/table reader and bounded heap decompression. No LabVIEW installation
  or third-party parser is needed at runtime.
- Return `None` when source is absent and a graph with no signals when source
  contains an empty diagram. Reject controls, unsupported heap variants,
  duplicate heaps and malformed resources. Missing source is not a passing
  security result.
- Preserve UID/class object definitions, their nearest identified enclosing
  object, DCO references, saved flags, primitive resource IDs and the distinct
  `paramIdx` and `parmIndex` fields. Classless UID references must not overwrite
  definitions. Preserve unknown object classes without inventing their behavior.
- Represent each signal as a net containing all saved terminal IDs, its owning
  diagram and its saved state. Do not infer direction from terminal-list order.
  Ignore compressed wire geometry. Resolve endpoint definitions after the
  whole heap has been read so forward references work.
- Retain unresolved, non-terminal, cross-diagram, duplicate and shared
  endpoints as explicit graph issues. Nets with fewer than two ends also
  carry an issue. Missing required identities/lists and duplicate definitions
  or scalar fields are malformed input errors rather than graph issues.
- Bound decoded heaps to the existing 64 MiB limit, graph objects and total
  signal endpoints to 100,000 each, and heap nesting to 256 scopes.
- Keep graph extraction separate from the current rule runner. Until a rule
  consumes the entry point, its unused-code expectation is explicit and
  limited to that entry point. Existing CLI behavior and rule extraction
  remain unchanged.

## Alternatives

- **Construct a graph on every scan:** adds work and new format requirements
  to unrelated rules. Extraction remains opt-in.
- **Drop unknown endpoints or assume a source from wire order:** could hide
  a path relevant to security analysis. Preserve the evidence and its issues.
- **Treat an issue-free graph as an executable VI:** rejected. The existing
  broken-wire fixture has resolvable endpoints; its saved signal state is
  retained without claiming to decode every broken-wire condition.
- **Resolve calls and implement taint propagation in this increment:** deferred.
  Both require independently validated semantics beyond structural topology.

## Consequences

This is a graph-reader foundation, not a new SAST rule or a complete dataflow
model. It does not resolve `LIbd` callees, front-panel names/direction through
`FPHb`, type descriptors, primitive names, tunnel transfers, local variables,
sanitizers or execution conditions. Absence of graph issues does not certify
any of those capabilities or imply safety.

Focused tests cover forward references, fan-out, nested diagram ownership,
malformed and unresolved connections, numeric widths, resource validation and
limits. Project-owned saved VI fixtures verify the measured control wire and
broken-wire topology, and the existing VI fixture corpus is read as a
regression check. Synthetic cases do not replace validation against additional
LabVIEW-saved branching and System Exec diagrams.

The next increment must identify the actual System Exec call and command
terminal from saved evidence, then add supported local transfer rules and
report incomplete paths explicitly. It must not report a call alone as a
vulnerability.

## References

- [Project identity and format references](0001-project-identity-and-format-references.md)
- [Windows and Linux compatibility](0002-windows-linux-compatibility.md)
- [Security analysis direction](0026-security-analysis-command-and-rules.md)
- `pylabview/LVheap.py`: UID/class attributes, `signalList`, `termList`,
  `objFlags`, `paramIdx`, `parmIndex`, `primResID`, `state`, and heap integers.
- `labview-mcp/experiments/pylabview/FINDINGS.md`: section 3, symbolic connections.
- `labview-mcp/experiments/aixml-without-grpc/FINDINGS.md`: fan-out, tunnels
  and call-node layout.

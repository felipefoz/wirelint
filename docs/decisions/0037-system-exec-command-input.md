# Control-influenced System Exec command input

- Status: Accepted
- Date: 2026-11-25

## Context

Calling an OS utility is normal LabVIEW behavior. A dependency on
`System Exec.vi` is not evidence of injection. The useful review case is a
front-panel control contributing to its command line, including through
local string construction.

Decision 0036 provides structural connectivity, but not call identity or
transfer semantics. The first rule should exercise that foundation against
saved callers without requiring a general-purpose dataflow interpreter.

## Decision

- Add `system-exec-command-input` to `sast`, enabled by default at `warning`
  severity, mapped to CWE-78 and CWE-88. Findings request review; they do not
  assert attacker access, shell invocation or exploitability.
- Resolve actual static call-node UIDs through `LIbd/BDHP/IUVI` records.
  Require the saved callee name and NI library path to identify System Exec.
  A name elsewhere in the resource, a custom VI with the same basename or a
  dependency without a matching call node is insufficient.
- Support the modern link layout used by LabVIEW 14.0 and newer. Bound list
  sizes and validate alignment, paths and termination. Unknown link records
  are errors because they have no independent length that permits safe
  skipping. Never scan arbitrary bytes for a plausible next record.
- Build the graph only when the parsed links identify a System Exec call
  and the rule is enabled and not suppressed. Normal quality scans and
  security files without matching calls do not construct a graph.
- Trace the command terminal only. An unrelated control or a control wired
  to standard input must not cause a finding. Do not report unwired calls or
  supported literal-only command construction.
- Initially support direct front-panel control sources, diagram constants
  and Concatenate Strings. Concatenation preserves control influence; it
  is not validation. Follow signal fan-out without inferring direction from
  endpoint order.
- Validate the pane against original callers saved by LabVIEW 2024:
  command line is `iUseDCO.paramIdx` 11; standard input is 10. The wired-input
  terminal flag is `0x8000`. Concatenate Strings uses class 62 with class-63
  DCOs whose low flag bit distinguishes output from input; an omitted DCO
  flag is zero. These callers validate parsing, not platform-specific
  command-execution behavior.
- Bound recursive transfer tracing to 128 operations and memoize visited
  inputs. Cycles and excessive depth are incomplete paths.
- Keep unsupported upstream operations, structure-boundary transfers,
  ambiguous connections, missing source and missing terminal metadata
  explicit. A recognized call whose command path cannot be classified
  produces an analysis error, not a clean result or an injection finding
  based solely on uncertainty. Proven influenced calls in the same file
  still produce a finding.
- Use the existing per-file finding model and shared severity, enablement,
  suppression and report behavior. Do not expose command strings or
  control defaults in findings.

## Alternatives

- **Warn on every System Exec dependency:** rejected because routine
  constant commands would be reported without evidence of influence.
- **Implement all primitives and structures first:** defers the useful
  direct case and grows an unvalidated interpreter. Extend coverage from
  representative saved fixtures instead.
- **Assume an unknown operation sanitizes its output:** could conceal a
  command-input path. Unknown transfer semantics remain incomplete.
- **Treat every unknown operation as vulnerable:** confuses missing parser
  coverage with evidence of a security issue.

## Consequences

Front-panel controls are potential external input, not inherently untrusted.
Whether anyone can alter them, which executable parses the arguments and
whether validation is sufficient remain review questions.

The rule does not follow arbitrary subVI bodies, dynamic calls, local or
global variables, property nodes, network/file sources, format functions or
structure tunnels. It does not certify constant commands as secure or
recognize sanitizers. Unsupported link kinds can cause analysis errors even
before a sink is resolved; users can disable the rule while its supported
format coverage is expanded.

Saved caller fixtures are created specifically for WireLint. They are
inspected statically and never executed, including during fixture creation.
Scanning requires neither LabVIEW nor the fixture-generation tooling.

## References

- [Format research and attribution](0001-project-identity-and-format-references.md)
- [Windows and Linux compatibility](0002-windows-linux-compatibility.md)
- [Security analysis direction](0026-security-analysis-command-and-rules.md)
- [Structural graph reader](0036-diagram-graph-reader.md)
- `pylabview/LVblock.py`: modern `LinkObjRefs` list framing.
- `pylabview/LVlinkinfo.py`: `LinkObjIUseToVILink`, basic/typed/offset
  link metadata, compact reference fields and saved search paths.
- `pylabview/LVmisc.py`: qualified names and variable-width type indices.
- `labview-mcp/experiments/aixml-without-grpc/FINDINGS.md`: subVI call
  slots, wired terminal flags and structure boundaries.
- [CWE-78](https://cwe.mitre.org/data/definitions/78.html)
- [CWE-88](https://cwe.mitre.org/data/definitions/88.html)

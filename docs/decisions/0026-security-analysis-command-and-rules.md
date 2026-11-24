# Security analysis command and rule category

- Status: Accepted
- Date: 2026-11-23

## Context

WireLint's rules so far target code-quality and source-control hygiene
(decision 0006 and its successors). A second, security-focused analysis mode
was proposed: static checks mapped to CWE identifiers, surfaced through
report formats security tooling actually consumes, distinct from the existing
Code Quality report.

Research against the local `pylabview`/`pylavi` clones (per decision 0001)
established which security-relevant LabVIEW facts are cheaply readable
without a block-diagram wire/dataflow graph, which WireLint's format layer
does not support today:

- `LIvi`: a flat, pre-parsed dependency list (already read for
  `orphaned-vi`) naming the VIs/classes/libraries a VI references.
- A per-VI flags word (already read for `auto-error-handling` and
  `debugging-status`) containing a `RemotePanel` bit.
- `DFDS`: an independent top-level resource holding front-panel and diagram
  default values, not reached by walking the block-diagram heap. Decision
  0030 later found it is compiled data, absent from source-only VIs; defaults
  are read from the `FPHb` heap instead.
- Call Library Function Node fields (`funcName`, `tagDLLPath`,
  `tagDLLName`), which exist only as fields on a generic block-diagram heap
  object. Reading them needs new node-subtype recognition in `heap.rs`: more
  work than a flag read, but still short of full wire/dataflow tracing.

True taint/dataflow analysis (tracing values from network or file reads to
sinks such as `System Exec.vi`, SQL queries, or dynamic VI loading) needs a
wire/node graph WireLint does not parse today. That is deferred as **Tier 2**.
This decision covers **Tier 1**: facts readable without that graph.

A separate, independently produced proposal for a LabVIEW SAST tool was also
reviewed. Its standards framing (CWE as the primary classification, OWASP and
IEC 62443 as supplementary) and its pattern-matching/local-dataflow/
interprocedural maturity levels are consistent with this decision and are
folded in below. Its proposed extraction mechanism — using NI VI Scripting
and VI Server to drive a running, licensed LabVIEW instance and build a
graph-based intermediate representation — is rejected; see Alternatives. Some
of its proposed "industrial and hardware security" checks (for example,
setpoint bounds or calibration-authorization checks) are not static-analysis
problems at all: they need an externally supplied specification of what a
safe value or an authorized actor is, not just better parsing. They are
excluded entirely rather than deferred to Tier 2.

## Decisions

- Add a `wirelint sast <folder>` command, parallel to `scan`, not a mode flag
  on `scan`. Reuse `scan::discover_files` and the same candidate
  extensions/exclusions.
- Print the selected scan type in terminal output for both commands, including
  empty scans, so shared CI logs identify the rule registry in use.
- Introduce a second static registry, `SECURITY_BUILT_INS`, next to
  `BUILT_INS`. Generalize `Config::parse`/`Config::load` and
  `analysis::analyze` to accept the active rule slice as a parameter instead
  of hardcoding `BUILT_INS`, so `scan` passes `BUILT_INS` and `sast` passes
  `SECURITY_BUILT_INS`. Keep one `Rule` trait and one runner; do not fork the
  execution model.
- Each command loads and validates its own YAML (`--config`), checked only
  against its own registry's rule IDs; one file is not required to serve both
  commands. Add `docs/wirelint-sast.example.yaml`, tested the same way
  `wirelint.example.yaml` is tested against `BUILT_INS`.
- Add `fn cwe(&self) -> &'static [&'static str]` to `Rule`, defaulting to
  `&[]` so existing quality rules need no change. Security rules return their
  mapped CWE IDs; a rule may map to more than one depending on what it
  matched.
- `wirelint rules` lists both registries, tagging each entry with its command
  (`scan`/`sast`) and any CWE IDs.
- Tier 1 rule set, enabled by default at `warning` severity (consistent with
  existing hygiene-rule defaults; none of these are confirmed-exploit
  findings on their own):
  - `remote-panel-enabled` — reads the `RemotePanel` bit. CWE-284, CWE-306.
  - `sensitive-dependency` — matches `LIvi` dependency entries against a
    **required** `sensitive-vis` option (name/path substrings); inert without
    configuration, following the `connector-pane-pattern` precedent, because
    WireLint has no authoritative built-in list of dangerous VI paths to
    assert. CWE depends on the matched entry's configured category (for
    example CWE-78 for an OS-command-execution VI); the option's exact shape
    and per-entry CWE tagging are worked out in that rule's own decision.
  - `hardcoded-secret-default` — scans string defaults (`FPHb`, decision 0030)
    and scalar diagram string constants (`BDHb`, decision 0031) for
    secret-shaped content. CWE-798, CWE-259.
  - `clfn-library-path` — reads CLFN DLL path/name fields once `heap.rs`
    recognizes the node subtype. CWE-427. Higher cost than the other three;
    implement last.
  - Each ships with its own decision record (format offsets, exact matching
    rules, false-positive handling, tests) when implemented, matching the
    existing one-rule-per-decision convention (0012-0024).
- Add a third `reports::Format` variant for GitLab's Security Report Schema
  (`sast` artifact type), alongside the existing `gitlab-code-quality` and
  `sarif` formats, and make it available only to `sast` so quality-rule
  findings cannot be mislabeled as security findings. Map WireLint's three
  severities onto GitLab's wider scale as Info to Info, Warning to Medium,
  Error to High, leaving Low/Unknown/Critical unused until a concrete need
  arises. Reuse the SHA-256(rule ID, NUL, path) fingerprint model from
  decision 0011 for the report's vulnerability `id`. Confirm the exact JSON
  field layout (schema version, `location`, `identifiers`) against GitLab's
  current published schema in a follow-up decision once implemented, the same
  way decision 0011 followed decision 0004.
- Represent CWE in SARIF with `external/cwe/cwe-NNN` tags in each rule's
  `properties.tags` (the convention CodeQL, Semgrep, and Bandit already use
  for GitHub code scanning's CWE filtering), not full SARIF
  `taxonomies`/`relationships` objects, to avoid added JSON surface area for
  no additional capability WireLint needs today.
- CWE stays the sole classification tag for v1. OWASP and IEC 62443 are
  reasonable supplementary standards — IEC 62443 in particular, given
  LabVIEW's industrial and test-equipment use — but adding a second and third
  tag namespace now is scope creep without a concrete consumer. Revisit if a
  specific rule needs one.
- Tier 2 (block-diagram wire/dataflow tracing) is out of scope for this
  decision and splits into two levels, matching standard taint-analysis
  practice:
  - **Tier 2a, local:** trace a value across wires within one block diagram
    (for example OS command injection or path traversal where the tainted
    string and the sink are in the same VI).
  - **Tier 2b, interprocedural:** trace a value across subVI call boundaries,
    needing a project-wide call graph built from the same dependency data
    `sensitive-dependency` reads, plus per-subVI input/output tainting.
  Record both in `docs/roadmap.md` as needing their own decision once a
  node/wire graph model exists; Tier 2b additionally needs Tier 2a.

### Amendment (2026-11-24): restrict the SAST report to `sast`

The initial implementation exposed `gitlab-sast` to both commands because
they share a `Report` type. A report produced by `wirelint scan` then labeled
quality findings as SAST vulnerabilities, which is misleading to GitLab
consumers. Restrict `gitlab-sast` to `wirelint sast`; `scan` continues to
support GitLab Code Quality and SARIF. This supersedes the earlier availability
choice above.

## Alternatives

- **Infer the scan type from findings:** rejected because scans without
  findings and summary-only output would not identify the active registry.
- **One command, a `--security` flag on `scan`:** mixes two audiences/report
  shapes into one report and complicates the failure-threshold story (a
  security finding and a style finding would share one exit code). A
  separate command keeps reports and defaults independent.
- **One shared registry with a `category` field:** would let `scan` and
  `sast` both read from `BUILT_INS`, but blurs "all built-ins enabled by
  default" between two different review audiences and would require every
  quality-rule consumer to filter by category. Two registries keep both
  commands' defaults simple.
- **Hardcode a default sensitive-VI list for `sensitive-dependency`:**
  rejected; no reference repo or authoritative source documents a maintained
  "dangerous LabVIEW VI" list, and asserting one WireLint cannot verify or
  keep current would produce misleading findings.
- **Full SARIF CWE taxonomy objects:** more complete, but adds JSON structure
  (`taxonomies`, `relationships`) with no behavior difference from tag-based
  CWE association for WireLint's current consumers.
- **Extract block diagrams via NI VI Scripting/VI Server instead of parsing
  RSRC/XML files directly:** rejected. It would require a running, licensed
  LabVIEW instance to analyze anything, contradicting decision 0001's
  "independent... static-analysis tool" identity and the CLI's existing
  contract that files are read without launching LabVIEW. It would also break
  decision 0002's Windows/Linux compatibility, since VI Scripting automation
  is a Windows-hosted LabVIEW feature. WireLint's direct binary/XML parsing
  stays the only extraction mechanism, however far dataflow analysis
  eventually goes.
- **Adopt numeric `LVSEC0NN`-style rule IDs:** rejected in favor of the
  existing stable, descriptive, kebab-case rule ID convention already used by
  every built-in rule.

## Consequences

`Config` and `analysis::analyze` take an explicit rule slice instead of a
hardcoded registry; existing `scan` behavior is unaffected, but configuration
tests now need a registry parameter. Two example YAML files and two `Config`
validations exist going forward; keeping them in sync as rules are added is
manual, the same as today's single file. Security findings read as "needs
review," not "confirmed vulnerability," because Tier 1 does not trace data
flow; severity defaults and finding messages must say so. A fourth report
format (GitLab Security Schema) adds a third severity-mapping table
alongside decision 0011's two.

## References

- [GitLab Security Report Schema](https://docs.gitlab.com/ee/development/integrations/secure.html)
  (exact field layout confirmed at implementation time)
- [GitHub code scanning SARIF support and CWE tagging convention](https://docs.github.com/en/code-security/reference/code-scanning/sarif-support)
- CWE identifiers: [MITRE CWE List](https://cwe.mitre.org/)
- Supplementary standards considered for future classification, not
  implemented in v1: [OWASP Top Ten](https://owasp.org/www-project-top-ten/),
  [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/),
  [IEC 62443](https://www.isa.org/standards-and-publications/isa-standards/isa-iec-62443-series-of-standards)

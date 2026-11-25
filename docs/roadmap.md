# Roadmap

This roadmap collects future work explicitly deferred in accepted decision
records. It is not a delivery schedule or a commitment to implement every item;
each item needs planning before work begins. Features resolved by later
decisions are omitted.

## CLI and configuration

- **Configuration discovery:** decide whether and how WireLint should discover
  configuration automatically. Configuration is currently loaded only from an
  explicit `--config` path. See
  [decision 0004](decisions/0004-cli-configuration-and-reports.md) and
  [decision 0006](decisions/0006-rule-runner-and-source-only-check.md).
- **Flexible exclusions:** plan general path and glob matching, command-line
  exclusions, and exclusion-list files, including their syntax and precedence
  relative to configured literal folder exclusions. See
  [decision 0004](decisions/0004-cli-configuration-and-reports.md) and
  [decision 0008](decisions/0008-folder-exclusions.md).
- **Quiet mode:** define a mode that further reduces terminal output. See
  [decision 0009](decisions/0009-summary-verbosity-and-scan-timing.md).

## Diagnostics

- **Application-wide diagnostic logging:** design log levels, destinations,
  configuration, and the diagnostic details to record. The deferred scope
  includes discovered paths and per-file and per-rule elapsed timings; normal
  terminal output currently omits these details. See
  [decision 0007](decisions/0007-concise-output-and-future-logging.md) and
  [decision 0009](decisions/0009-summary-verbosity-and-scan-timing.md).

## CI reports

- **Expanded report workflows:** plan support for multiple report formats in
  one invocation, automatic repository-root detection, and direct report
  uploads. Currently, one format can be written per invocation, callers choose
  the scan root, and reports are written to local files. See
  [decision 0011](decisions/0011-ci-code-quality-reports.md).

## Security analysis

- **Local dataflow/taint tracing (Tier 2a):** trace a value across wires
  within one block diagram, for example OS command injection or path
  traversal where the tainted string and the sink are in the same VI. Needs
  validated direction, node transfer and structure-boundary semantics beyond
  the opt-in structural graph reader in
  [decision 0036](decisions/0036-diagram-graph-reader.md). The reader preserves
  terminal-UID nets and explicit unresolved connections; it does not yet
  resolve callees or perform taint analysis. `System Exec.vi` command-input
  analysis is a priority independent of tier ordering. See
  [decision 0026](decisions/0026-security-analysis-command-and-rules.md).
- **Interprocedural dataflow/taint tracing (Tier 2b):** trace a value across
  subVI call boundaries using a project-wide call graph, for example SQL
  injection or insecure deserialization where the tainted source and the sink
  are in different VIs. Needs Tier 2a plus per-subVI input/output tainting.
  See [decision 0026](decisions/0026-security-analysis-command-and-rules.md).
- **GitLab Security Report Schema:** the `gitlab-sast` report format is
  implemented in [decision 0032](decisions/0032-gitlab-sast-report.md).

## Releases

- **Commit-driven version bumps:** trigger releases from every push to `main`
  instead of only pushes that change `[package].version`, computing the next
  version from Conventional Commits (e.g. via git-cliff's `--bumped-version`)
  rather than a maintainer editing `Cargo.toml`. Needs its own decision on
  what counts as a releasable change, since every commit type would then
  decide whether a release happens at all. See
  [decision 0023](decisions/0023-automated-changelog-and-tagging.md).


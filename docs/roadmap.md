# Roadmap

This roadmap collects ideas for future work and work explicitly deferred in
accepted decision records. It is not a delivery schedule or a commitment to
implement every item; each item needs planning before work begins. Features
resolved by later decisions are omitted.

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
- **Automatic fixes:** explore an opt-in `--fix` option for applicable findings,
  inspired by [Ruff's fix workflow](https://docs.astral.sh/ruff/linter/#fixes).
  Consider safe fixes by default, explicit opt-in for unsafe fixes, selecting
  fixable rules, and a preview of proposed changes without writing files.
  Plan how to preserve LabVIEW file integrity, handle unsupported or conflicting
  fixes, and report applied and remaining findings. Decide which commands and
  rules can support fixes before implementation.

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

- **Broader local dataflow/taint tracing (Tier 2a):** extend the initial
  System Exec command-input rule beyond direct controls, constants and
  Concatenate Strings. Add saved fixtures and transfer semantics for format
  functions, structure tunnels and additional external sources; expand static
  call-link coverage. Unsupported paths currently produce analysis errors.
  The opt-in graph foundation is described in
  [decision 0036](decisions/0036-diagram-graph-reader.md), and the initial rule in
  [decision 0037](decisions/0037-system-exec-command-input.md).
- **Interprocedural dataflow/taint tracing (Tier 2b):** trace a value across
  subVI call boundaries using a project-wide call graph, for example SQL
  injection or insecure deserialization where the tainted source and the sink
  are in different VIs. Needs Tier 2a plus per-subVI input/output tainting.
  See [decision 0026](decisions/0026-security-analysis-command-and-rules.md).

## Releases

- **Commit-driven version bumps:** trigger releases from every push to `main`
  instead of only pushes that change `[package].version`, computing the next
  version from Conventional Commits (e.g. via git-cliff's `--bumped-version`)
  rather than a maintainer editing `Cargo.toml`. Needs its own decision on
  what counts as a releasable change, since every commit type would then
  decide whether a release happens at all. See
  [decision 0023](decisions/0023-automated-changelog-and-tagging.md).


# CLI: scanning folders

Build and run WireLint from the repository:

```text
cargo run -- scan path/to/labview/project
```

Or, after building or installing the executable:

```text
wirelint scan path/to/labview/project
```

The scan command recursively searches the specified folder and runs enabled
built-in analysis rules. Extension matching is case-insensitive. Files are read
without launching LabVIEW or modifying source files.

The initial candidate extensions are:

- `.vi`
- `.vit`
- `.vim`
- `.ctl`
- `.lvproj`
- `.lvclass`
- `.lvlib`

`.llb` archives are not included. Symbolic links encountered below the scan root
are skipped. Discovery uses extensions; the format readers then inspect file
contents for analysis.
YAML `exclude-folders` entries prune matching directories at any depth before
traversal. The [configuration template](../wirelint.example.yaml) excludes
`.git` and `.lv-venv`; load it with `--config` to apply those exclusions.

## Rules and configuration

```text
wirelint rules
wirelint scan path/to/project --config checks.yaml
wirelint scan path/to/project --fail-on warning
wirelint sast path/to/project --config sast-checks.yaml
```

All rules in the selected command are enabled by default, with their default
severities. `scan` rules check compiled-code separation, saved LabVIEW version
bounds (default minimum `20.0`, no maximum), file descriptions, VI debugging
status, and saved block diagram breakpoints. The `no-breakpoints` rule defaults to
`error` severity, so findings fail the default threshold. Other built-in rules
default to `warning`, which does not fail the default `error` threshold.
The `debugging-status` rule flags debugging-enabled VIs by default.
Set its YAML option `fail-when: disabled` to flag the opposite state.
The `saved-version` rule accepts inclusive `minimum-version` and
`maximum-version` YAML options. Setting only a maximum applies no minimum.
`sast` uses a separate rule registry and configuration. Its
`hardcoded-secret-default` rule flags credentials stored in VI string
defaults and scalar diagram string constants: values of credential-named
controls or constants, key/value assignments, URL credentials, private keys,
and well-known token formats. `system-exec-command-input` reviews front-panel
control influence on NI System Exec's command line through direct wires or
Concatenate Strings. Unsupported command paths are analysis errors, not
passing checks. SAST findings
indicate content that needs review, not confirmed
exploitable vulnerabilities. See the
[security rule reference](sast-rules.md#hardcoded-secret-default).

Without `--config`, WireLint uses built-in defaults; no YAML file is required.
All rules are enabled, the failure threshold is `error`, and no folders are
excluded. `--config <FILE>` loads an explicit YAML file; there is no automatic
discovery.

`--fail-on <error|warning|none>` overrides the built-in or YAML failure
threshold, so it also works without `--config`. See the
[configuration guide](configuration.md), [quality rules](quality-rules.md),
and [security analysis rules](sast-rules.md).

## Full scan command example

The scan options can be combined in one invocation. This example loads
`checks.yaml`, overrides its failure threshold, prints individual findings,
and writes a GitLab code quality report:

```text
wirelint scan . --config checks.yaml --fail-on warning --verbose --format gitlab-code-quality --output gl-code-quality-report.json
```

`--format` and `--output` must be used together. See [CI report files](#ci-report-files)
for report behavior and format details.

## Output and exit statuses

The terminal report starts with the number of discovered files and a message
that enabled rules are running, followed by the scan type: `scan (quality)`
or `sast (security)`. It does not list every discovered path.
By default, findings are summarized by severity and rule, without individual
file paths or messages. Rule totals are sorted by rule ID; rules with no
findings are omitted. If there are no findings, both breakdowns are omitted.

For example:

```text
Found 120 supported LabVIEW file(s). Running enabled rules...
Scan type: scan (quality)
Analyzed 120 file(s); 35 finding(s); 0 analysis error(s).
Elapsed scan time: 0.123 s.
Findings by severity: 0 info; 35 warning; 0 error.
Findings by rule:
  separate-compiled-code: 35 finding(s).
```

Use `--verbose` (or `-v`) to include individual findings before the same
summary:

```text
wirelint scan path/to/project --verbose
```

Individual findings and analysis errors include their relative file paths,
in sorted file order within each group. Analysis errors remain visible in
both modes. Verbosity does not change analysis, counts, or exit status.
Results are reported after analysis finishes; the initial message is not a
per-file progress indicator.

Skipped enabled rules are always printed on stdout with their file paths when
suppressed by a [VI bookmark or XML description directive](quality-rules.md#skipping-a-rule-with-a-bookmark).
They do not appear in CI reports or count as findings.

The final summary counts successfully analyzed files, findings, and analysis
errors. Files with format/read errors are not counted as analyzed, and analysis
errors are separate from error-severity findings. Errors go to stderr, while
the initial message, verbose findings, and summary go to stdout. Other files
are still analyzed after individual file errors.

Elapsed scan time uses a monotonic clock and is printed in seconds to three
decimal places in both modes, including empty scans and scans with analysis
errors. Timing starts just before discovery and stops when analysis finishes;
it includes the initial status output, but excludes configuration loading and
final report rendering. A failure before analysis completes can prevent the
final summary. There are no per-file or per-rule timers.

| Status | Meaning |
| --- | --- |
| `0` | No errors and no findings at or above the configured failure threshold |
| `1` | Findings meet or exceed the threshold |
| `2` | Command-line, configuration, discovery, output, or analysis error |

The scan folder must exist and be a directory. A folder with no matching files
prints a message and a zero-count summary and exits successfully, provided
configuration and output are valid. Unsupported binary formats are errors,
not passing checks. `--fail-on none` suppresses finding-based failures only,
not analysis errors.

## CI report files

```text
wirelint scan . --format gitlab-code-quality --output gl-code-quality-report.json
wirelint sast . --format gitlab-sast --output gl-sast-report.json
wirelint scan . --format sarif --output wirelint.sarif
```

`--format` and `--output` must be supplied together. Each invocation writes one
UTF-8 JSON report without a byte order mark. The terminal summary, `--verbose`,
and exit thresholds are unchanged. Existing report files are overwritten; the
parent directory must already exist. Destinations resolving to discovered input
files or the loaded configuration are rejected.

The GitLab Code Quality format is named `gitlab-code-quality`. The shorter
`gitlab` name remains accepted as an alias for existing scripts.

Reports include all findings regardless of the failure threshold. Empty scans
and disabled rules produce empty findings. Reports are written after completed
analysis even when the exit status is `1` or `2`. Configuration or discovery
failures before analysis do not produce a report; a report write error returns
`2`. Do not upload a stale report left by an earlier invocation.

Paths are relative to the **scan folder**, with forward-slash separators.
For CI, scan the repository root (`.` from the checkout root) so paths match
tracked files. SARIF paths are percent-encoded URIs, including spaces and `#`.
Non-UTF-8 finding paths are rejected rather than changed to lossy names.

LabVIEW VIs do not have source lines. GitLab requires a positive line number,
so `location.lines.begin` is always **1**, a file-level placeholder, not a
diagram position. GitLab SAST and SARIF use file-only locations without a
line/region. None of these formats provides diagram navigation; inline PR/MR
annotations may not appear for binary files.

| WireLint severity | GitLab Code Quality | GitLab SAST | SARIF |
| --- | --- | --- | --- |
| `info` | `info` | `Info` | `note` |
| `warning` | `minor` | `Medium` | `warning` |
| `error` | `major` | `High` | `error` |

The `gitlab-sast` format writes the GitLab Security Report Schema with
`scan.type: sast`, CWE identifiers, stable finding IDs, and file-level
locations. It maps severities to `Info`, `Medium`, and `High`, respectively.
Unlike Code Quality, the SAST report also records analysis errors as fatal
scan messages and marks the scan as failed.

Fingerprints identify the relative file path and rule. They remain stable
across message/severity changes and different checkout locations; moving a
file changes its fingerprint.

Analysis errors remain on stderr and force status `2`. SARIF records them as
failed invocation notifications, and GitLab SAST records them as fatal scan
messages, separate from findings. GitLab Code Quality has no analysis-error
channel: **check the process status**, since an empty Code Quality report can
accompany a failed/incomplete scan.

See [CI integration](ci-reports.md) for GitLab and GitHub upload examples.

## Deferred features

See the [project roadmap](../roadmap.md) for features explicitly deferred in
the decision records.
Use `wirelint --help` and `wirelint scan --help` for CLI help.

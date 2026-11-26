# Rule fixtures

Quality and security fixtures are grouped by rule ID under `quality/` and
`sast/`. Files can produce findings for rules other than the one named by their
folder. `quality/support/` contains additional parser regression fixtures.

Run both commands from the repository root and inspect their findings and
analysis errors:

```text
cargo run -- lint tests/fixtures --verbose --fail-on none
cargo run -- security tests/fixtures --verbose --fail-on none
```

The connector-pane fixtures include a normal VI and global and polymorphic VIs.
The rule requires its fixture-specific configuration:

```text
cargo run -- lint tests/fixtures/quality/connector-pane-pattern --config tests/fixtures/quality/connector-pane-pattern/checks.yaml --verbose --fail-on none
```

The saved-version folder contains a LabVIEW-saved VI and a synthetic XML
library. Its configuration reports the VI above, and the library below, the
permitted LabVIEW 20.0 release:

```text
cargo run -- lint tests/fixtures/quality/saved-version --config tests/fixtures/quality/saved-version/checks.yaml --verbose --fail-on none
```

The password-protected VI uses the fixture-only password
`WireLintFixtureOnly-2026`.

The `quality/path-usage` VIs were saved and run by LabVIEW without file
operations. The ordinary empty and absolute constant and absolute default
fixtures should produce findings; the relative and dedicated Empty Path
fixtures should not. `Relative Colon Path.vi` is invalid for Windows but valid
for Linux and exercises `targets`. `Path Usage Values.vi` combines several
values to exercise the per-file finding count. Dedicated Not a Path is covered
by synthetic heap tests; no LabVIEW-saved fixture was generated for it.

The separate-compiled-code folder contains a LabVIEW-saved VI and a synthetic
XML library. They exercise the VI save-record flag and the library's
`NI.LV.All.SourceOnly` property respectively.

The auto-error-handling folder contains an enabled standard VI and genuine
global and polymorphic negative fixtures. The latter two have their saved flag
clear: LabVIEW rejects enabling it through VI Server with error 1035. Synthetic
reader tests cover both flag states for these kinds. Only the standard VI
should produce an auto-error-handling finding.

The orphaned-vi `url-less-items` fixture is a synthetic library containing
both an unsaved VI item without a URL and a normal member URL. The URL-less
item should not cause an analysis error or discard the normal member.

The System Exec callers are original diagrams saved by LabVIEW 2024.
**Do not run these VIs:** their command strings are test data for static
analysis, and the callers were never executed during fixture creation.

| Caller in `sast/system-exec-command-input/` | Expected rule result |
| --- | --- |
| `constant-command.vi` | No warning |
| `constant-concatenate-command.vi` | No warning |
| `control-command.vi` | Warning |
| `concatenate-command.vi` | Warning |
| `control-other-input.vi` | No warning; control feeds standard input only |
| `unwired-system-exec.vi` | No warning; intentionally broken required command input |
| `suppressed-control-command.vi` | Rule skipped by a diagram directive |

These callers use NI's `<vilib>/Platform/system.llb/System Exec.vi`. The
saved command slot is 11, while standard input is 10. Tests inspect these
files without needing the NI library or launching LabVIEW.

# Rule fixtures

Quality and security fixtures are grouped by rule ID under `quality/` and
`sast/`. Files can produce findings for rules other than the one named by their
folder. `quality/support/` contains additional parser regression fixtures.

Run both commands from the repository root and inspect their findings and
analysis errors:

```text
cargo run -- scan tests/fixtures --verbose --fail-on none
cargo run -- sast tests/fixtures --verbose --fail-on none
```

The connector-pane fixtures include a normal VI and global and polymorphic VIs.
The rule requires its fixture-specific configuration:

```text
cargo run -- scan tests/fixtures/quality/connector-pane-pattern --config tests/fixtures/quality/connector-pane-pattern/checks.yaml --verbose --fail-on none
```

The saved-version folder contains a LabVIEW-saved VI and a synthetic XML
library. Its configuration reports the VI above, and the library below, the
permitted LabVIEW 20.0 release:

```text
cargo run -- scan tests/fixtures/quality/saved-version --config tests/fixtures/quality/saved-version/checks.yaml --verbose --fail-on none
```

The password-protected VI uses the fixture-only password
`WireLintFixtureOnly-2026`.

The separate-compiled-code folder contains a LabVIEW-saved VI and a synthetic
XML library. They exercise the VI save-record flag and the library's
`NI.LV.All.SourceOnly` property respectively.

The auto-error-handling folder contains an enabled standard VI and genuine
global and polymorphic negative fixtures. The latter two have their saved flag
clear: LabVIEW rejects enabling it through VI Server with error 1035. Synthetic
reader tests cover both flag states for these kinds. Only the standard VI
should produce an auto-error-handling finding.

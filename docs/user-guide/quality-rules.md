# Quality and hygiene rules

WireLint calls its static-analysis tests **rules**, to distinguish them from
the Rust tests that verify WireLint itself. List the built-in rules with:

```text
wirelint rules
```

These quality and source-control hygiene rules run with `wirelint scan`. All
are enabled by default and have a stable ID, default severity, and shared
`enabled` and `severity` configuration options. See
[configuration](configuration.md) for YAML examples and exit thresholds.
For security analysis rules, see the separate
[SAST rule reference](sast-rules.md).

## Rules

- [separate-compiled-code](#separate-compiled-code)
- [file-description](#file-description)
- [saved-version](#saved-version)
- [debugging-status](#debugging-status)
- [no-breakpoints](#no-breakpoints)
- [auto-error-handling](#auto-error-handling)
- [password-set](#password-set)
- [orphaned-vi](#orphaned-vi)
- [class-mutation-history](#class-mutation-history)
- [terminal-style](#terminal-style)
- [connector-pane-pattern](#connector-pane-pattern)
- [path-usage](#path-usage)

## Execution order

WireLint reads discovered files sequentially in sorted path order, parsing each
once into shared facts. It then runs enabled rules in file path order and
built-in registry order:

```text
File A: read/parse once
File B: read/parse once
File A: Rule 1 -> Rule 2 -> ...
File B: Rule 1 -> Rule 2 -> ...
```

Rules reuse the shared facts without rereading files. The `orphaned-vi` rule
also compares facts across the scan before rules run. Neither files nor rules
run in parallel. A finding does not stop other rules or files. If reading or
parsing fails, WireLint records an analysis error and skips rules for that
file; the remaining files are still analyzed.

If all rules are disabled, discovery still runs, but file contents are not
read or parsed. Findings and errors are reported after analysis finishes.

## Skipping a rule with a bookmark

Add a free label to a VI's block diagram containing exactly:

```text
#wirelint-ignore file-description
```

Replace `file-description` with any built-in rule ID. Matching is
case-sensitive; the directive consists of two whitespace-separated tokens.
An unlinked diagram directive skips that enabled rule for that file, even if it
would otherwise pass. Repeated directives skip it only once. Other bookmarks,
unlinked front-panel labels, owned labels, unknown rule IDs, and disabled rules
have no effect.
Nested diagram free labels are included. Every skipped rule is printed with
its file path on stdout, with or without `--verbose`; it does not contribute a
finding or affect the failure threshold. CI reports contain findings, not skips.

The reader supports compressed version-b (`BDHb` and `FPHb`) source heaps.
Unsupported source heap formats,
malformed heaps, or heaps over 64 MiB cause an analysis error. Controls cannot
use these directives. Reading file facts still happens before rules are
skipped, so a directive does not suppress format or I/O errors.

### Ignoring one object with a comment arrow

For `path-usage`, `hardcoded-secret-default`, and `system-exec-command-input`,
use the same directive in a free label and attach its LabVIEW comment arrow to
the object being exempted. WireLint resolves the saved attachment reference,
not the label's position, name, or visual proximity.

- Paths: point at the scalar constant or front-panel path control. A diagram
  arrow to the control's terminal also exempts that control's saved default.
- Secrets: point at the string constant or front-panel control. An exemption
  on a control applies to all strings in its saved value, including nested
  array/cluster fields; it does not exempt other controls.
- System Exec: point at the particular call node, not its input control or
  upstream string constant. Other calls remain analyzed.

Linked front-panel free labels are supported in VI panes; unlinked front-panel
labels do not create file-wide exceptions. Controls (`.ctl`) remain unsupported.
Arrows to structures do not exempt their descendants, and arrows to harmless
neighbors do not exempt nearby findings. Object ignores are applied before a
rule counts and summarizes its remaining offending values.

Applied object ignores are printed with the source heap and object UID, for
example `skipped [path-usage] on BDHb object 123`. Duplicate directives for the
same rule/object produce only one skip record.

A dangling, ambiguous, or cross-diagram arrow is an analysis error, never a
fallback to a file-wide ignore. A linked directive for an enabled VI-wide rule
is also an analysis error: remove its arrow to request the existing file-wide
behavior. Unknown and disabled rules do not produce skip records.
Neither linked nor file-wide directives suppress malformed metadata or
incomplete System Exec analysis.

### XML description directives

For `.lvproj`, `.lvlib`, and `.lvclass` files, put each directive on its own
line in the file's native description:

```text
Shared instrument drivers.

#wirelint-ignore separate-compiled-code
#wirelint-ignore saved-version
```

Projects use `NI.Project.Description`; libraries and classes use
`NI.Lib.Description`. Only the root owner's `Str` property applies, not nested
item descriptions, XML comments, or other properties. Surrounding whitespace
on each line is ignored. Prose containing a directive inline does not skip a
rule. Multiple directives and duplicates follow the same rules as VI bookmarks.

Directive lines are excluded when checking `file-description`: a description
containing only directives still produces a finding unless that rule is
explicitly skipped too. Descriptions are read and validated even when
`file-description` is disabled, because directives may skip other enabled rules.
If all rules are disabled, files are still not read.

## `path-usage`

Warns about ordinary scalar path constants that are empty, scalar path
constants and front-panel defaults that are absolute, and relative path
components with invalid target-platform syntax. Dedicated Empty Path and
Not a Path nodes are allowed, as are relative paths and LabVIEW's Not a Path
value. The rule does not check whether a file exists.

```yaml
rules:
  path-usage:
    enabled: true
    severity: warning
    targets: [windows, linux]
```

`targets` accepts `windows`, `linux`, or both. Both are checked by default;
syntax invalid on either selected platform is reported. Checks are independent
of the host OS. Windows checks include forbidden characters, trailing spaces
or periods, and reserved device names. Linux checks reject NUL and separators
inside a component. Absolute paths are reported regardless of `targets`.

This initial reader examines scalar `stdPath` objects in VI source heaps. It
does not inspect path values inside arrays or clusters, string values converted
to paths, or paths built at runtime. It includes saved indicator defaults.
Malformed or unsupported path records produce an analysis error rather than
an assumed valid path. A file produces at most one finding, with the first
offending object and a count of additional values.

## `separate-compiled-code`

Requires **Separate compiled code from source** to be enabled.

| Setting | Value |
| --- | --- |
| Default enablement | Enabled |
| Default severity | `warning` |
| Applies to | `.vi`, `.vit`, `.vim`, `.ctl`, `.lvlib`, `.lvclass`, `.lvproj` |
| Rule-specific options | None |

Keeping compiled code separate helps avoid source-control changes caused only
by recompilation. This rule checks the stored setting, not the presence or
absence of a compiled-code resource.

### How the setting is read

- **Binary VI-family files** (`.vi`, `.vit`, `.vim`, `.ctl`): locate the `LVSR`
  save-record resource through the RSRC metadata. Read bit 10 (`0x00000400`,
  `SourceOnly`) in the big-endian `viFlags2` word at offset 8 of the LVSR
  payload. A clear bit means false.
- **XML files**: read the direct child property named `NI.LV.All.SourceOnly`,
  with `Type="Bool"`, on the document root (`Project`, `Library`, or `LVClass`).
  `true` passes; `false` or an absent property produces a finding. Whitespace
  around Boolean text is ignored. Nested items and comments do not supply the
  owner's setting.

Each discovered file is checked independently. Project, library, and class
properties control separation for new items; enabling them does not prove that
existing members have separation enabled. WireLint does not inherit these
values, follow member references outside the scanned folder, or modify files.

### Configuration

```yaml
rules:
  separate-compiled-code:
    enabled: true
    severity: warning
```

The expected value is always true. Disable the rule to opt out; there is no
option to require embedded compiled code.

### Findings and analysis errors

Findings contribute to the default summary totals. Use `--verbose` to show
individual findings, for example:

```text
Example.vi: warning [separate-compiled-code]: Enable separate compiled code from source (source-only setting).
```

A warning is counted but does not fail the default `error` threshold. Use
`--fail-on warning` or configure severity `error` when separation must gate CI.

Malformed input is an **analysis error**, not a disabled setting or a passing
check. Errors are written to stderr with the file path in both output modes;
other files are still analyzed. Analysis errors always cause exit status 2,
even with `--fail-on none`.

The initial reader supports RSRC format 3, creator `LBVW`, VI/control/template
types `LVIN`, `LVCC`, `sVIN`, and `sVCC`, with one uncompressed `LVSR` section
at index 0 and a save record of at least 68 bytes. Older/unknown formats,
missing or ambiguous save records, inconsistent headers, and out-of-bounds
records are errors. XML must be well-formed UTF-8 (a UTF-8 BOM is accepted);
wrong root elements, duplicate owner properties, wrong property types, and
invalid Boolean values are errors. The reader does not validate the contents
of every unrelated RSRC resource.

## `file-description`

Requires a non-empty native description for each supported LabVIEW file. It
defaults to enabled with `warning` severity and applies to `.vi`, `.vit`,
`.vim`, `.ctl`, `.lvclass`, `.lvlib`, and `.lvproj`. Context Help is not
required.

The rule reads only the description belonging to the file itself:

- **VI-family files**: the first string in the `STRG` resource is the owning
  VI's description. An absent, empty, whitespace-only, or LabVIEW nonbreaking
  space-only description produces a finding.
- **Projects**: the direct owner property `NI.Project.Description`, with
  `Type="Str"`.
- **Libraries and classes**: the direct owner property `NI.Lib.Description`,
  with `Type="Str"`.

Missing XML properties and blank or directive-only XML descriptions produce
findings. Nested item properties do not count. Duplicate or malformed owner properties and malformed
`STRG` records are analysis errors, not passing descriptions. Use
`--verbose` to show findings, for example:

```text
Example.vi: warning [file-description]: Add a non-empty description to this LabVIEW file.
```

The rule checks the native description field only; it does not inspect VI
Context Help or modify files.

Binary descriptions are read from the first string in an uncompressed
`STRG` section. The reader supports the corresponding string layouts for
pre-4.0 and 4.0-or-newer LabVIEW files; unsupported or malformed records are
analysis errors.

## `saved-version`

Requires each file's saved LabVIEW major.minor release to fall within the
configured inclusive bounds. It defaults to a minimum of `20.0`, no maximum,
and reports a `warning`. It applies to `.vi`, `.vit`, `.vim`, `.ctl`, `.lvproj`,
`.lvclass`, and `.lvlib`.

```yaml
rules:
  saved-version:
    enabled: true
    severity: warning
    minimum-version: '20.0'
    maximum-version: '21.0'
```

Set either bound or both. With only `maximum-version`, no minimum applies;
with neither bound, the default minimum of `20.0` applies. Equal bounds
require exactly that major.minor release. A minimum greater than the maximum
is a configuration error, even when the rule is disabled.

Quote both version options: each must be a major.minor string, with a major from
0 to 99 and a minor from 0 to 9. Comparison is numeric, not decimal or
lexicographic. Patch, build, and prerelease stage are ignored. These bounds
check saved release metadata; they do not guarantee runtime compatibility.

The former `minimum-saved-version` ID is rejected with a migration message.
Rename its configuration key to `saved-version`; existing `minimum-version`
options keep their meaning. Findings and CI reports also use the new ID,
so existing saved-version findings receive new report fingerprints.

For VI-family files, the version word is at offset 0 in the `LVSR` save-record
payload. For XML files, the root's `LVVersion` attribute encodes the same
version word as hexadecimal, potentially without leading zeroes. The first
three version digits encode the major and minor release. A missing or
malformed version is an analysis error while this rule is enabled; disabling
the rule skips version validation. Each file is checked independently, not
against its owning project, library, or class.

## `debugging-status`

Checks the stored **Allow debugging** setting for `.vi`, `.vit`, and `.vim`
files. The rule is enabled by default, reports `warning` findings, and flags
debugging when it is enabled.

```yaml
rules:
  debugging-status:
    enabled: true
    severity: warning
    fail-when: enabled
```

Set `fail-when: disabled` to flag VIs with debugging disabled instead.
This option accepts only `enabled` or `disabled`; it is separate from the
rule's Boolean `enabled` option. Findings follow the usual severity and
failure-threshold policy: default warnings do not fail a scan unless
`--fail-on warning` is used or the rule severity is changed to `error`.

The reader follows pylabview's `DebugCapable` definition: bit 9
(`0x00000200`) of the big-endian `instrState` word at offset 24 in the
`LVSR` payload. Other instrument-state bits do not enable debugging.
This checks the saved flag, not whether a debugging session is active.

VI and VI-template resource types (`LVIN`, `sVIN`) supply the flag. Controls
(`LVCC`, `sVCC`) and XML projects, libraries, and classes do not have an
applicable VI execution setting and produce no findings for this rule under
either policy. The existing RSRC format limitations and analysis-error
handling apply; malformed save records are not treated as debugging disabled.

Use `--verbose` to show findings:

```text
Example.vi: warning [debugging-status]: Debugging is enabled. Disable Allow debugging in VI Properties > Execution.
```

WireLint does not change the VI's settings.

## `no-breakpoints`

Disallows VIs saved with block diagram breakpoints. It is enabled by default
with `error` severity, so findings fail the default CI threshold. It applies
to VI and VI-template files (`.vi`, `.vit`, `.vim`); controls and XML
containers have no applicable breakpoint state and are skipped.

The rule reads the LVSR **Breakpoints Set** flag in the saved VI state
(payload word at offset 24, mask `0x20000000`). It detects the saved flag, not
individual breakpoint locations, and does not modify the VI. Remove saved
breakpoints in LabVIEW before committing. The rule has no specific options;
use the common `enabled` and `severity` options to override its defaults.

```yaml
rules:
  no-breakpoints:
    enabled: true
    severity: error
```

Use `--verbose` to show findings:

```text
Example.vi: error [no-breakpoints]: Remove all block diagram breakpoints before committing this VI.
```

## `auto-error-handling`

Warns about automatic error handling on VIs and VI templates (`.vi`, `.vit`,
`.vim`). It is enabled by default with `warning` severity, so findings do not
fail the default CI threshold. Global and polymorphic VIs have no executable
diagram of their own and are skipped, even when the saved flag is enabled.
Controls and XML project, library, and class files are also skipped.

The rule reads bit 29 (`0x20000000`) of the LVSR `viFlags2` word at payload
offset 8. The big-endian `viType` field at LVSR payload offset 34 identifies
global (`4`) and polymorphic (`11`) VIs. Other VI types retain the flag check.
This is the saved **Enable automatic error handling** setting in VI
Properties > Execution. Disable that setting in LabVIEW and save the VI to
resolve a finding. WireLint does not change the setting.

```yaml
rules:
  auto-error-handling:
    enabled: true
    severity: warning
```

Use `--verbose` to show findings:

```text
Example.vi: warning [auto-error-handling]: Automatic error handling is enabled. Disable 'Enable automatic error handling' in VI Properties > Execution.
```

## `password-set`

Warns when a VI or VI template has a password set. The rule is enabled by
default with `warning` severity and applies to `.vi`, `.vit`, and `.vim`; it
does not apply to controls or XML project/library/class files.

The reader checks the VI's `BDPW` password-hash resource against LabVIEW's
empty-password hash marker. It does not reveal, retain, or validate a password.
If the resource is absent, the VI is treated as having no password. Malformed
password metadata is an analysis error when this rule is enabled.

```yaml
rules:
  password-set:
    enabled: true
    severity: warning
```

Use `--verbose` to show findings:

```text
Example.vi: warning [password-set]: This VI has a password set. Remove it if the VI should remain editable.
```

## `orphaned-vi`

Rejects a VI that has an owning-library link but is not listed as a member by
that library. The rule is enabled by default with `error` severity and applies
to VI and VI-template files (`.vi`, `.vit`, `.vim`), not controls.

WireLint reads the VI's `VILB` entry in its `LIvi` linker table and compares its
relative `PTH0` owner path with the `.lvlib` files discovered in the same scan.
Owner paths are relative to the VI file, with each empty `PTH0` component
moving up one level. It then checks the library's `Item Type="VI"` URLs,
including items nested in folders. These URLs are relative to the library
file: `../Member.vi` names a VI beside that file. A VI is reported only when
its referenced library is also scanned and does not list that VI. External,
absolute/token, and unscanned library paths cannot be checked and are skipped.
VI items without a `URL` attribute have no saved file path and are skipped
without rejecting the library or its other members. Explicitly empty URLs
remain analysis errors; other member URL handling is unchanged.

```yaml
rules:
  orphaned-vi:
    enabled: true
    severity: error
```

Use `--verbose` to show findings:

```text
orphan-vi.vi: error [orphaned-vi]: This VI points to a library that does not list it.
```

Add the VI to its owning library in LabVIEW, or remove/fix the stale library
link. WireLint does not modify either file.

## `class-mutation-history`

Warns when `.lvclass` XML contains nonempty content in the direct `Property` on
the `LVClass` root with `Name="NI.LVClass.Geneology"` and `Type="Xml"`. The
rule is enabled by default with `warning` severity.
Projects, libraries, and VI-family files do not apply and produce no findings.

```yaml
rules:
  class-mutation-history:
    enabled: true
    severity: warning
```

Nonempty text or child elements in the property produce a finding. An absent,
empty, or whitespace-only value passes. Nested properties and properties with
a different type are ignored. WireLint does not validate the history data or
modify the class file.

Use `--verbose` to show findings:

```text
Example.lvclass: warning [class-mutation-history]: This LabVIEW class contains mutation-history content in its NI.LVClass.Geneology XML property.
```

## `terminal-style`

Requires every front-panel control/indicator terminal on a VI's block
diagram to use the same preferred display style: **icon style** (the
control's own icon) or **data-type style** (a compact glyph for its data
type), set per terminal with the block diagram's **View As Icon**
context-menu item. The rule is enabled by default with `warning` severity,
defaults to requiring data-type style, and applies to VI and VI-template
files (`.vi`, `.vit`, `.vim`); controls have no block diagram and are
skipped.

```yaml
rules:
  terminal-style:
    enabled: true
    severity: warning
    preferred-style: data-type
```

Set `preferred-style: icon` to require icon style instead. This option
accepts only `data-type` or `icon`; it is separate from the rule's Boolean
`enabled` option. A VI with zero or one terminal cannot have a mismatched
terminal and always passes.

Use `--verbose` to show findings:

```text
Example.vi: warning [terminal-style]: This VI has 2 terminal(s) not using data type display. Disable View As Icon on the block diagram for the affected controls and indicators.
```

### How the setting is read

Each front-panel terminal is a `fPTerm` object in the VI's compressed
version-b block diagram heap (`BDHb`). Bit 26 (`0x04000000`) of its 32-bit
`objFlags` field is set for icon-style display and clear for data-type
style; other bits are unrelated to this rule. The reader reuses the same
bounded `BDHb` heap walk as [bookmark directives](#skipping-a-rule-with-a-bookmark);
the same format limitations apply, including the 64 MiB heap size bound and
support for only the compressed version-b format. WireLint does not change
any terminal's display style.

## `connector-pane-pattern`

Restricts a VI's connector pane to a configured set of allowed terminal
patterns, each one of LabVIEW's 36 fixed layouts chosen in the Icon/connector
pane editor. The rule is enabled by default with `warning` severity and
applies to VI and VI-template files (`.vi`, `.vit`, `.vim`). Controls and
global and polymorphic VIs have no connector pane and are skipped.

```yaml
rules:
  connector-pane-pattern:
    enabled: true
    severity: warning
    allowed-patterns:
      - "4x2x2x4"
```

`allowed-patterns` is required and must name at least one pattern from the
table below; unknown names are a configuration error. Without a configured
`allowed-patterns` list, the rule is inert: it reports nothing, and a VI's
connector pane data is not read at all, so malformed connector pane data in
that case is not an analysis error either. A VI is reported only when its own
pattern's name is not in the configured set; the finding repeats the
configured names so the message is self-contained:

```text
Example.vi: warning [connector-pane-pattern]: This VI's connector pane uses pattern '2x1', which is not in the allowed set: 4x2x2x4.
```

### Allowed pattern names

Names match the LabVIEW Wiki's published shape notation for each pattern
(for example `4x2x2x4`), not a LabVIEW on-screen label; LabVIEW does not
name patterns in its own connector pane menu.

| Name | Terminals | Name | Terminals |
| --- | --- | --- | --- |
| `1` | 1 | `3x2x2x4` | 11 |
| `1x1` | 2 | `4x2x3` | 9 |
| `2x1` | 3 | `4x1x1` | 6 |
| `3` | 3 | `4x1x2` | 7 |
| `3x1` | 4 | `4x1x3` | 8 |
| `2x2` | 4 | `4x1x1x4` | 10 |
| `4` | 4 | `4x2x1` | 7 |
| `3x2` | 5 | `4x2x2` | 8 |
| `4x1` | 5 | `4x2x1x4` | 11 |
| `4x2` | 6 | `2x1x1` | 4 |
| `3x3` | 6 | `3x1x1` | 5 |
| `4x3` | 7 | `3x1x2` | 6 |
| `4x4` | 8 | `5x2x2x2x5` | 16 |
| `4x1x4` | 9 | `6x2x2x2x2x6` | 20 |
| `4x2x4` | 10 | `8x2x2x2x2x2x2x8` | 28 |
| `4x2x2x4` | 12 | | |
| `3x2x1` | 6 | | |
| `3x2x2` | 7 | | |
| `3x2x3` | 8 | | |
| `3x2x4` | 9 | | |
| `3x2x2x3` | 10 | | |

### How the setting is read

The pattern is read from the VI's `CONP` block (a single type index into the
VI's `VCTP` consolidated type pool) and the `Function`-type Type Descriptor
it names: a right shift by 3 of that Type Descriptor's raw `pattern` field
gives the pattern's position in the table above. `VCTP` is always zlib-coded,
with the same 64 MiB size bound as the block-diagram heap reader. A missing
or malformed `CONP`/`VCTP` chain, an unexpected Type Descriptor, or a pattern
code outside the 36 known patterns are each an analysis error, but only while
`allowed-patterns` is configured. A `PolyVI` (`0xF2`) or `Cluster` (`0x50`)
descriptor identifies a VI without a connector pane. See
[decision 0034](../decisions/0034-pane-less-vi-descriptors.md) and
[decision 0024](../decisions/0024-connector-pane-pattern-rule.md) for the
format research. WireLint does not change the VI's connector pane.

## Adding a built-in rule

The [rule architecture decision](../decisions/0006-rule-runner-and-source-only-check.md)
describes the extension contract:

1. Add any necessary facts to the format layer, with bounded parsing and
   malformed-input tests. Reuse shared facts; do not read files inside a rule.
2. Implement `Rule` with a stable kebab-case ID, description, default severity,
   and a check that returns a message for violations.
3. Register the implementation in `BUILT_INS`. The runner handles enablement,
   severity overrides, finding paths, and failure thresholds.
4. Add focused Rust tests and document the quality rule here, including
   defaults, applicable types, options, limitations, and remediation.

Rule-specific options must be typed and validated; do not accept arbitrary
options or silently ignore unknown keys.

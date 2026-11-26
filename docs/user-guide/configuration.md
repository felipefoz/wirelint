# Rule configuration

Without a configuration file, WireLint enables every built-in rule with its
default severity, uses the `error` failure threshold, and excludes no folders.

Load YAML explicitly:

```text
wirelint lint path/to/project --config checks.yaml
```

There is no automatic configuration-file discovery. The configuration path is
relative to the current working directory, not the scanned folder.

Check a configuration before scanning:

```text
wirelint config check checks.yaml
```

This validates the complete file, including both rule registries, without
reading any LabVIEW files.

Create an example configuration or display the effective configuration:

```text
wirelint config init checks.yaml
wirelint config show checks.yaml
wirelint config show
```

`init` requires a destination whose parent exists and never overwrites an
existing file. The example excludes `.git` and `.lv-venv` and sets a connector
pane pattern, so it differs from the built-in defaults. `show` validates its
optional file and prints YAML with defaults and overrides for both categories.
Without a file, it shows built-in defaults without discovering a config file.
For legacy top-level rules, it places the overrides in their inferred category.
The output omits `allowed-patterns` when no connector pane restriction applies
and omits absent version bounds.

## Configuration template

Copy [`wirelint.example.yaml`](../wirelint.example.yaml) as a starting point,
or use it directly for `lint` from the repository root:

```text
wirelint lint path/to/project --config docs/wirelint.example.yaml
```

The same file configures both command-specific registries. `lint.rules` and
`security.rules` keep their options separate:

```text
wirelint security path/to/project --config docs/wirelint.example.yaml
```

The [configuration template](../wirelint.example.yaml) lists every rule in both
registries. Rust tests check the listed rules and their default severities.
The connector pane pattern is an example restriction, not a built-in default.
Adjust `enabled` and `severity` in your copy to
select the checks and levels for your project. It excludes folders named
`.git` and `.lv-venv` at any depth.

## Schema

```yaml
version: 1
fail-on: error
exclude-folders:
  - .git
  - .lv-venv
lint:
  rules:
    separate-compiled-code:
      enabled: true
      severity: warning
    saved-version:
      enabled: true
      severity: warning
      minimum-version: '20.0'
    debugging-status:
      enabled: true
      severity: warning
      fail-when: enabled
    no-breakpoints:
      enabled: true
      severity: error
security:
  rules:
    hardcoded-secret-default:
      enabled: true
      severity: warning
```

| Key | Accepted values | Default |
| --- | --- | --- |
| `version` | `1` | `1` |
| `fail-on` | `error`, `warning`, `none` | `error` |
| `exclude-folders` | List of literal folder names | `[]` (no exclusions) |
| `lint.rules` | Mapping of lint rule IDs to option mappings | No overrides |
| `security.rules` | Mapping of security rule IDs to option mappings | No overrides |
| `<category>.rules.<id>.enabled` | YAML Boolean | `true` |
| `<category>.rules.<id>.severity` | `info`, `warning`, `error` | Rule default |
| `lint.rules.saved-version.minimum-version` | Quoted `major.minor` string | `'20.0'` if neither bound is set; otherwise no implicit minimum |
| `lint.rules.saved-version.maximum-version` | Quoted `major.minor` string | No maximum |
| `lint.rules.debugging-status.fail-when` | `enabled`, `disabled` | `enabled` |
| `lint.rules.connector-pane-pattern.allowed-patterns` | Nonempty list of pattern names (see [quality rules](quality-rules.md#connector-pane-pattern)) | Required; no default, rule is inert until set |
| `lint.rules.no-breakpoints` | Common `enabled` and `severity` options only | Enabled, `error` |

Fields may be omitted. An omitted rule remains enabled; an empty category rule
map does not disable built-ins. An empty options mapping also retains defaults.
Use `{}` for a configuration with no overrides.

Unknown rule IDs, unknown options, duplicate keys, unsupported schema versions,
invalid YAML, and invalid option values are errors. WireLint reports the
configuration path and exits with status 2 before scanning. This version
supports a single YAML document; custom scripts are not supported. Rule-specific
options are accepted only for the rule that defines them. Rule IDs are checked
against their section's registry, so a lint rule under `security.rules` or a
security rule under `lint.rules` is a configuration error. The organization
uses schema version 1; the split does not require a version change. Existing
configurations with top-level `rules` remain accepted as legacy, single-command
files and cannot combine that key with non-empty `lint.rules` or
`security.rules` maps.

The `saved-version` bounds are inclusive. Set only `maximum-version` for an
upper-bound-only check, or set both bounds to the same value to require an
exact major.minor release. A minimum greater than the maximum is an error.
Explicit `null` bounds are invalid; omit an unwanted bound instead.
Rename the former `minimum-saved-version` rule key to `saved-version`;
the old key is rejected with migration guidance.

## Folder exclusions

Use `exclude-folders` to skip entire directory trees during discovery:

```yaml
exclude-folders:
  - .git
  - .lv-venv
```

Each entry matches an exact folder name, case-sensitively on both Windows and
Linux, at any depth below the scan root. For example, `.git` skips both
`.git` and `nested/.git`, but not `.git-backup` or `.GIT`. Excluded folders are
not traversed, and their files are not counted, read, or analyzed.

Entries are names, not paths or glob patterns. Empty/blank names, `.` and `..`,
NUL characters, and names containing either path separator (`/` or `\`) are
configuration errors. The scan root itself is always scanned, even if its name
matches an exclusion. Exclusions affect directories only, not similarly named
files.

Omitting the field or using `exclude-folders: []` keeps every folder eligible
for scanning. The `.git` and `.lv-venv` exclusions apply only when loading the
template or another configuration that lists them; the template is not loaded
automatically. Use `--config` as shown above. Command-line exclusion options
and exclusion-list files are not implemented yet.

## Enablement and severity

To disable the first rule:

```yaml
lint:
  rules:
    separate-compiled-code:
      enabled: false
```

To make a violation an error:

```yaml
lint:
  rules:
    separate-compiled-code:
      severity: error
```

Severity controls the finding's reported level. `fail-on` independently
controls whether those findings fail the scan:

- `error`: fail for error findings.
- `warning`: fail for warning or error findings.
- `none`: never fail because of findings.

For `debugging-status`, `enabled` controls whether the rule runs, while
`fail-when` selects which stored debugging state produces a finding. For
example, require debugging to be enabled and make violations fail CI:

```yaml
lint:
  rules:
    debugging-status:
      enabled: true
      severity: error
      fail-when: disabled
```

By default, the rule reports debugging-enabled VIs at `warning` severity.
Despite its name, `fail-when` does not override the severity or exit threshold.

Info findings do not fail any available threshold. Configuration, discovery,
file-read, and format errors always fail, independently of this threshold.
The default summary and `--verbose` mode count the same findings and use the
same threshold; verbosity is a CLI presentation option, not a YAML setting.

The command-line threshold overrides YAML:

```text
wirelint lint path/to/project --config checks.yaml --fail-on warning
```

If all rules are disabled, discovery still runs, but file contents are not read
and the analyzed count is zero. No content validation is claimed in this mode.

See the [quality and hygiene rule reference](quality-rules.md) and the
[security rule reference](sast-rules.md) for each rule's defaults and
interpretation, and the [CLI guide](cli.md) for output and exit statuses.
General path/glob exclusions and machine report formats are not implemented
in this version.

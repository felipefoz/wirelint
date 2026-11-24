# CI code quality reports

- Status: Accepted
- Date: 2026-11-18

## Context

Decision 0004 selected GitLab Code Quality JSON and GitHub SARIF. The current
rules report file-wide properties, and binary LabVIEW files have no source
lines. CI consumers need stable identities and repository-relative locations
without changing terminal summaries or failure thresholds.

## Decisions

- Add paired `--format gitlab-code-quality|sarif` and `--output FILE` options
  to `scan`. Both are required together. Write one report per invocation while
  preserving terminal output, verbosity, and exit statuses. Keep these options
  out of YAML. Accept `gitlab` as a compatibility alias for
  `gitlab-code-quality`.
- Paths are relative to the scan root, with `/` separators. CI must scan the
  repository root. Reject non-UTF-8 finding paths rather than replacing bytes
  and potentially identifying the wrong file. SARIF paths are percent-encoded
  relative URIs; GitLab paths are plain JSON strings.
- GitLab requires `location.lines.begin`: use `1` as a file-level placeholder
  for all current findings, including XML files. This is not a diagram position.
  SARIF uses file-only physical locations with no `region`.
- Map `info`, `warning`, and `error` to GitLab `info`, `minor`, and `major`,
  and SARIF `note`, `warning`, and `error`, respectively.
- Use SHA-256 of rule ID, a NUL delimiter, and normalized relative path for
  fingerprints in both formats. Exclude message, severity, absolute root, and
  timing. Current rules produce at most one finding per rule/file. Future
  rules producing multiple findings per file must extend this identity model.
- SARIF 2.1.0 includes built-in rule metadata, effective finding levels, and a
  versioned `wirelintFileRule/v1` partial fingerprint. Analysis errors become
  invocation error notifications and set `executionSuccessful` to false.
  Finding-based exit status 1 does not mean the analyzer failed.
- GitLab reports only rule findings because its format has no analysis-error
  channel. Always preserve stderr diagnostics and status 2; an empty GitLab
  report must not be interpreted as a complete successful scan on its own.
- Write reports after completed analysis even on statuses 1 or 2, including
  empty arrays/results. Early configuration/discovery errors do not generate
  reports. Existing reports are overwritten, parent directories are not
  created, and write failures return status 2. Reject destinations resolving
  to discovered inputs or the loaded configuration before writing.
- Use `serde_json` for correct JSON escaping and `sha2` for stable SHA-256,
  rather than hand-written JSON, an unstable standard-library hasher, or a
  homegrown hash implementation. No platform SDK or upload dependency is needed.

### Amendment (2026-11-24): descriptive GitLab format name

Use `gitlab-code-quality` as the canonical name to distinguish this report
from GitLab's separate `gitlab-sast` report. Retain `gitlab` as an alias so
existing scripts continue to work.

## Alternatives and consequences

A placeholder line in SARIF would imply a source location that does not exist;
file-only locations are supported. GitLab has no corresponding file-only
representation, so line 1 is necessary. Neither format provides meaningful
diagram annotations, and binary files may not show inline PR/MR annotations.

Reports on stdout would require rerouting terminal output. Separate report
files preserve existing scripts and interactive output. Multiple formats in one
invocation, automatic repository-root detection, and direct uploads are deferred.

## References

- [GitLab Code Quality report format](https://docs.gitlab.com/ci/testing/code_quality/#code-quality-report-format)
- [GitHub SARIF support](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support)

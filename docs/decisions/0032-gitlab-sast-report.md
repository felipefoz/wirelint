# GitLab SAST report format

- Status: Accepted
- Date: 2026-11-24

## Context

Decision 0026 added `wirelint sast` and committed to a third report format for
GitLab's Security Report Schema, while deferring the precise JSON shape.
GitLab ingests this report through `artifacts:reports:sast`; it is distinct
from the existing Code Quality report even though both are JSON.

## Decisions

- Add the `gitlab-sast` `--format` value to `sast` without changing the
  existing `gitlab-code-quality` format. Reject it for `scan` so quality-rule
  findings cannot be emitted as SAST vulnerabilities.
- Emit the GitLab SAST schema version `15.2.5`, with the schema URI,
  `scan.type: sast`, WireLint analyzer/scanner metadata, UTC start and end
  timestamps, scan status, and a `vulnerabilities` array.
- Map each finding to a vulnerability with `id` equal to the existing SHA-256
  identity (rule ID, NUL, normalized relative path), `category: sast`, a
  rule-description name, the finding message as description, and a file-only
  `location.file`. Do not invent line numbers for LabVIEW files.
- Include a primary `wirelint_rule` identifier and one `cwe` identifier for
  each CWE mapped by the rule. CWE values are the numeric suffixes, with
  canonical MITRE URLs.
- Map `info`, `warning`, and `error` to GitLab `Info`, `Medium`, and `High`.
- Analysis errors remain on stderr and force process status `2`; in this
  format they also set `scan.status` to `failure` and appear as fatal scan
  messages. Findings alone do not mark the analysis scan as failed.
- Derive timestamps from the captured analysis start and finish wall-clock
  times. Keep the existing standard-library-only dependency set.
- Document the `artifacts:reports:sast` integration and distinguish this
  format from Code Quality and SARIF.

## Alternatives

- **Reuse `--format gitlab-code-quality` for security findings:** rejected
  because GitLab ingests Code Quality and SAST through different artifact
  types and expects different schemas.
- **Allow `gitlab-sast` on `scan`:** rejected because it labels quality checks
  as security vulnerabilities, misleading GitLab consumers.
- **Use file line 1 in the SAST location:** rejected; the SAST schema permits
  a file-only location, and a placeholder line would imply false precision.
- **Use only CWE identifiers as primary identifiers:** rejected because
  multiple WireLint rules may map to the same CWE. The stable WireLint rule
  identifier is primary; CWE identifiers supplement it.
- **Add a date/time dependency:** rejected; the required UTC timestamp format
  can be produced from `SystemTime` without a platform-specific command or
  dependency.

## Consequences

GitLab can consume security findings through its SAST artifact interface, and
the report carries stable per-rule/per-file IDs plus CWE metadata. GitLab
Security Report Schema locations remain file-level because WireLint has no
source-line model for LabVIEW diagrams. The schema version is pinned in the
serializer and should be updated alongside schema validation if GitLab changes
its supported report format.

## References

- [GitLab security scanner integration](https://docs.gitlab.com/development/integrations/secure/)
- [GitLab SAST report schema](https://gitlab.com/gitlab-org/security-products/security-report-schemas/-/blob/master/dist/sast-report-format.json)
- [Security analysis command and rule category](0026-security-analysis-command-and-rules.md)
- [CI code quality reports](0011-ci-code-quality-reports.md)

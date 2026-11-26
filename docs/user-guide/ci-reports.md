# CI code quality reports

WireLint exports GitLab Code Quality JSON, GitLab SAST reports, and SARIF
2.1.0 for GitHub code scanning. Run it from the checkout root and scan `.` so
reported paths match repository paths. See the
[CLI guide](cli.md#ci-report-files) for locations, severity mapping,
fingerprints, and error behavior.

These examples assume `wirelint` is already built or installed on the runner.
They do not require LabVIEW. Choose `--fail-on warning` to fail on warnings
as well as errors; the default threshold is `error`.

## GitLab

Add a job to your pipeline:

```yaml
wirelint:
  script:
    - wirelint lint . --format gitlab-code-quality --output gl-code-quality-report.json --fail-on warning
  artifacts:
    when: always
    reports:
      codequality: gl-code-quality-report.json
    paths:
      - gl-code-quality-report.json
```

Reports are available even if findings or analysis errors fail the job. Do not
allow status `2` to pass silently: GitLab reports contain findings only, not
analysis errors. Run the job on the target branch too so merge requests can
compare findings against a baseline.

GitLab requires line numbers. WireLint uses line 1 as a file-level placeholder;
it does not identify a location inside a LabVIEW diagram.

## GitLab SAST

Use the separate security-analysis command and declare the generated file as
a SAST artifact:

```yaml
wirelint_sast:
  script:
    - wirelint security . --format gitlab-sast --output gl-sast-report.json
  artifacts:
    when: always
    reports:
      sast: gl-sast-report.json
    paths:
      - gl-sast-report.json
```

By default, warning findings do not fail the job, so the report can be
ingested while still surfacing findings. If the job fails, GitLab may retain
the artifact without ingesting it as a security report. Analysis errors are
recorded as fatal scan messages; they also produce process status `2`.
Vulnerability locations identify files only because WireLint does not parse
LabVIEW diagram source lines. CWE identifiers are included for rules that map
to a CWE.

## GitHub

Add these steps to a job after checkout and WireLint installation:

```yaml
permissions:
  contents: read
  security-events: write

steps:
  # Checkout and install/build WireLint before these steps.
  - name: Run WireLint
    id: wirelint
    run: wirelint lint . --format sarif --output wirelint.sarif --fail-on warning

  - name: Upload WireLint SARIF
    if: ${{ !cancelled() && steps.wirelint.outcome != 'skipped' && hashFiles('wirelint.sarif') != '' }}
    uses: github/codeql-action/upload-sarif@v4
    with:
      sarif_file: wirelint.sarif
      category: wirelint
```

The upload runs even when the scan fails, provided a report exists. The failed
scan step still fails the job. Use a clean checkout/report destination to avoid
uploading an old report after an early failure.

GitHub code scanning must be available and enabled for the repository.
Permissions can be restricted for fork pull requests; follow your repository's
security policy rather than granting untrusted workflows extra access.

SARIF findings refer to entire files, with no fabricated line number.
GitHub may show file-level alerts without inline pull request annotations,
especially for binary VIs. Analysis errors appear as invocation notifications,
not additional rule violations.

## References

- [GitLab Code Quality](https://docs.gitlab.com/ci/testing/code_quality/)
- [GitLab security scanner integration](https://docs.gitlab.com/development/integrations/secure/)
- [Uploading SARIF to GitHub](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/integrate-with-existing-tools/upload-sarif-file)

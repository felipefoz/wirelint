# Security analysis rules

Security rules run with `wirelint sast` and are listed separately from the
quality and source-control hygiene rules used by `wirelint scan`. They read
stored facts from LabVIEW files; they do not trace block-diagram dataflow.
Findings are review signals, not confirmation of exploitability.

All SAST rules are enabled by default and use the shared `enabled` and
`severity` options. Use the separate
[SAST configuration template](../wirelint-sast.example.yaml), and see the
[configuration guide](configuration.md) for schema and exit-threshold details.

## Rules

- [hardcoded-secret-default](#hardcoded-secret-default)

## `hardcoded-secret-default`

Reports VI string defaults containing a non-placeholder value assigned to a
credential-like key.

| Setting | Value |
| --- | --- |
| Default enablement | Enabled |
| Default severity | `warning` |
| CWE | CWE-798, CWE-259 |
| Applies to | VI-family resources (`.vi`, `.vit`, `.vim`) |
| Rule-specific options | None |

The rule matches explicit assignments using keys such as `password`, `secret`,
`token`, `api_key`, `access_key`, and `private_key`, with `=` or `:` as the
assignment separator. Common template values, environment-variable references,
and empty values are ignored. Unlabeled strings are not classified as secrets;
the finding is a review signal, not confirmation of exploitability. Its
message never includes the stored value. Remove the credential or load it from
an appropriate secret store at runtime.

The format reader extracts serialized `DFDS` string defaults but does not map
them to front-panel labels or inspect block-diagram string constants. The rule
therefore cannot detect unlabeled credentials, diagram constants, or secrets
stored in other data types.

Rule suppression directives are shared across commands. Their syntax and
limitations are documented in the
[quality and hygiene rule reference](quality-rules.md#skipping-a-rule-with-a-bookmark).

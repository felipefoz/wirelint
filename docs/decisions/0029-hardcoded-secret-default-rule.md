# Hardcoded secret default rule

- Status: Accepted
- Date: 2026-11-23

## Context

Decision 0026 defines `hardcoded-secret-default` as the first Tier 1 SAST
rule. Decision 0027 adds bounded extraction of raw string defaults from a
VI's `DFDS` stream, leaving secret matching to rule consumers. The rule must
identify useful review candidates without exposing their values in terminal
or CI reports, and without claiming to perform dataflow analysis.

The current format reader does not map defaults to front-panel labels or read
block-diagram string constants. The rule can therefore only evaluate the
extracted string contents.

## Decision

- Register `hardcoded-secret-default` in the SAST registry, enabled by default
  at `warning` severity, with CWE-798 and CWE-259 mappings.
- Inspect extracted `DFDS` strings for explicit assignments to a
  case-insensitive credential-key list: `password`, `passwd`, `pwd`, `secret`,
  `token`, `api_key`, `api-key`, `apikey`, `access_key`, `access-key`,
  `client_secret`, `client-secret`, `private_key`, `private-key`,
  `credential`, and `credentials`.
- A key may be preceded by non-alphanumeric text and followed by optional
  ASCII whitespace, `=` or `:`, optional whitespace, and a nonempty value.
  Quoted values end at their matching quote. Unquoted values end at ASCII
  whitespace, comma, semicolon, ampersand, or `}`.
- Ignore empty values; exact `changeme`, `change_me`, `change-me`,
  `placeholder`, `redacted`, `dummy`, `example`, `test`, `none`, `null`,
  `undefined`, `xxxx`, and `****` values (case-insensitive); values beginning
  with `your_`, `your-`, `your `, `$`, `${` with a closing `}`, `{{` with a
  closing `}}`, or `<` with a closing `>`.
- Emit at most one finding per file. The message describes the credential-like
  assignment but never includes its stored value.
- Add `docs/wirelint-sast.example.yaml` and user-guide coverage for the rule
  and the separate SAST configuration registry.

## Alternatives

- **Entropy-only detection:** rejected for the first rule because it flags
  arbitrary identifiers and does not reliably distinguish secrets from
  ordinary data.
- **Detect every string containing terms such as `password`:** rejected
  because prompts and documentation often mention credentials without
  containing a credential value.
- **Read block-diagram constants or decode front-panel labels now:** deferred.
  The existing parser does not expose those facts; extending it requires
  separate format work and tests.
- **Include matched values in findings:** rejected because reports are commonly
  shared with CI systems and reviewers; repeating a credential would increase
  its exposure.

## Consequences

The rule catches explicit, labeled credential assignments while avoiding
unlabeled high-entropy values. Matching is intentionally a heuristic: a string
that resembles a credential assignment can be a false positive, and secrets
without a recognized key are missed. Findings are review signals, not proof of
exploitability. The rule only sees `DFDS` defaults supported by the current
reader; it does not inspect diagram constants, other data types, or runtime
dataflow.

## References

- [Security analysis command and rule categories](0026-security-analysis-command-and-rules.md)
- [Typed default-data reader](0027-typed-default-data-reader.md)

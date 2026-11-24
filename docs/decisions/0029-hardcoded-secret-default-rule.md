# Hardcoded secret default rule

- Status: Accepted
- Date: 2026-11-23

## Context

Decision 0026 defines `hardcoded-secret-default` as the first Tier 1 SAST
rule. Decision 0027 adds bounded extraction of raw string defaults from a
VI's default values (from `FPHb` since decision 0030), leaving secret
matching to rule consumers. The rule must
identify useful review candidates without exposing their values in terminal
or CI reports, and without claiming to perform dataflow analysis.

The initial format reader did not map defaults to front-panel labels or read
block-diagram string constants. Decisions 0030 and 0031 extend those inputs.

### Amendment (2026-11-23): label-aware matching

Explicit `key=value` matching alone missed the most common LabVIEW pattern: a
string control labeled `Password` whose default is the secret itself. It also
missed quoted JSON keys, XML elements, URL credentials, and well-known token
formats, and reported masks such as `********` and prompts such as
`Password: Enter here`. A real VI's `VCTP` pool showed that the Type
Descriptors of those front-panel controls stored their labels (`HasLabel` flag,
trailing Pascal string). A later VI showed that this does not hold for every
control; decision 0030 describes the front-panel name-label reader.

## Decision

- Register `hardcoded-secret-default` in the SAST registry, enabled by default
  at `warning` severity, with CWE-798 and CWE-259 mappings. Implement it in
  `rules::sast::hardcoded_secret`, with its matchers in the same module;
  `rules::sast` only registers rules.
- Extend the typed default reader to attach a label path to each extracted
  string: the control's front-panel name when available, otherwise its Type
  Descriptor label, and one Type Descriptor label per cluster/array level,
  empty where none is stored. Locate a descriptor label as pylabview
  does: in the last 256 bytes after the decoded properties, the first length
  byte whose printable text runs exactly to the descriptor's end. A missing
  label is empty, not an error.
- Classify each default or scalar string constant with the strongest matching heuristic:
  1. PEM/PGP private-key headers, and fixed-prefix token formats with bounded
     character sets and word boundaries: AWS access key IDs, GitHub, GitLab,
     Slack, Google API, Stripe live keys, and signed JWTs.
  2. The innermost non-empty label names a credential and the whole value is
     plausible.
  3. Text assigns a plausible value to a credential name with `=`, `:`, `:=`,
     or `=>`, including quoted keys; an XML element holds one; URL userinfo
     holds a password; or `Authorization:` is followed by a `Bearer`, `Basic`,
     `Token`, or `Digest` credential. `==`, `!=`, `<=`, `>=`, and `://` are
     not separators.
- Use one name classifier for labels, keys, and XML element names. Split names
  into lowercase words at non-alphanumeric bytes and camel-case boundaries. A
  name is a credential when a word (or its singular) ends in `password`,
  `passwd`, `passwort`, `kennwort`, `passphrase`, `passcode`, `pwd`, `secret`,
  `token`, `credential`, `apikey`, `accesskey`, `secretkey`, `privatekey`, or
  `accountkey`, or when `key`/`keys` follows `api`, `access`, `secret`,
  `private`, `account`, `encryption`, `signing`, `master`, `auth`, `client`,
  or `session`. Words describing metadata (`hint`, `length`, `policy`, `file`,
  `path`, `name`, `id`, `type`, `url`, `prompt`, `pattern`, and similar)
  exclude the name.
- A value is plausible when, after trimming, it has at least four bytes; is
  not a listed placeholder (`changeme`, `example`, `none`, `true`, ...); is
  not one repeated byte; does not start with `$`, `your_`, or `your-`; is not
  wrapped in `{{ }}`, `< >`, `% %`, or `[ ]`; contains no prompt word
  (`enter`, `please`, `type`, `your`, `here`, `required`, `optional`,
  `must`); and is not prose. A value with whitespace is prose when it ends
  with `.`, `!`, or `?`, or contains a credential term as a word (`The
  password is incorrect!`). Bare credential words such as `password`,
  `secret`, or `token` are placeholders. Token formats and private keys do not apply this filter.
- Emit at most one finding per file. It names the first match's labels (or
  its `VCTP` type entry and field path), sanitized and truncated to 64
  characters, names the matching heuristic, and counts other matches. It never
  includes a stored value.
- Implement matchers as bounded byte scans without a regular-expression
  dependency; key lookbehind and XML names are capped at 128 bytes.

## Alternatives

- **Entropy-only detection:** rejected because it flags arbitrary identifiers
  and does not reliably distinguish secrets from ordinary data. Entropy as a
  secondary filter on named values remains a possible refinement.
- **Detect every string containing terms such as `password`:** rejected
  because prompts and documentation often mention credentials without
  containing a credential value.
- **Use only Type Descriptor labels:** rejected after a real control with an
  unlabeled descriptor demonstrated that this misses named defaults. The
  front-panel heap supplies its name; "Password Display" remains out of scope.
- **Use the `regex` crate:** rejected for now. The token formats are fixed
  prefixes with one character set each, which a small scanner handles without
  a new dependency.
- **Report confidence tiers as separate severities or rules, with rule
  options and fingerprints for suppression:** deferred until findings from
  real projects show which tiers need different handling.
- **Ignore block-diagram string constants:** rejected after a credential-named
  constant demonstrated the gap; see decision 0031.
- **Include matched values in findings:** rejected because reports are commonly
  shared with CI systems and reviewers; repeating a credential would increase
  its exposure.

## Consequences

The rule now reports the typical LabVIEW case, a credential-named control with
a stored default, plus vendor tokens and private keys anywhere in a string,
while ignoring masks, prompts, template references, and metadata labels.
Matching remains a heuristic: credential-like names with ordinary values can
be false positives, and values shorter than four bytes or without a recognized
name or format are missed. The finding message now contains user-chosen label
text. Findings are review signals, not proof of exploitability. The rule only
sees supported front-panel defaults (decision 0030) and scalar diagram string
constants (decision 0031); it does not inspect composite diagram constants,
other data types, or runtime dataflow.

## References

- [Security analysis command and rule categories](0026-security-analysis-command-and-rules.md)
- [Typed default-data reader](0027-typed-default-data-reader.md)
- `pylabview/LVdatatype.py`: `TYPEDESC_FLAGS.HasLabel` and `parseRSRCDataFinish`

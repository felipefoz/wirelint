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

### Amendment (2026-11-23): label-aware matching

Explicit `key=value` matching alone missed the most common LabVIEW pattern: a
string control labeled `Password` whose default is the secret itself. It also
missed quoted JSON keys, XML elements, URL credentials, and well-known token
formats, and reported masks such as `********` and prompts such as
`Password: Enter here`. A real VI's `VCTP` pool showed that the Type
Descriptors selected by `TM80` store each control's label (`HasLabel` flag,
trailing Pascal string), so labels can be read without the front-panel heap.

## Decision

- Register `hardcoded-secret-default` in the SAST registry, enabled by default
  at `warning` severity, with CWE-798 and CWE-259 mappings. Implement it in
  `rules::sast::hardcoded_secret`, with its matchers in the same module;
  `rules::sast` only registers rules.
- Extend the typed default reader to attach a label path to each extracted
  string: one Type Descriptor label for the type-map entry and one per
  cluster/array level, empty where none is stored. Locate a label as pylabview
  does: in the last 256 bytes after the decoded properties, the first length
  byte whose printable text runs exactly to the descriptor's end. A missing
  label is empty, not an error.
- Classify each default with the strongest matching heuristic:
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
  wrapped in `{{ }}`, `< >`, `% %`, or `[ ]`; and contains no prompt word
  (`enter`, `please`, `type`, `your`, `here`, `required`, `optional`,
  `must`). Token formats and private keys do not apply this filter.
- Emit at most one finding per file. It names the first match's labels (or
  its type-map entry and field path), sanitized and truncated to 64
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
- **Read labels from the front-panel heap (`FPHb`):** deferred. Type
  Descriptor labels are already reachable from the default-data walk; the heap
  would add the "Password Display" flag but needs separate format work.
- **Use the `regex` crate:** rejected for now. The token formats are fixed
  prefixes with one character set each, which a small scanner handles without
  a new dependency.
- **Report confidence tiers as separate severities or rules, with rule
  options and fingerprints for suppression:** deferred until findings from
  real projects show which tiers need different handling.
- **Read block-diagram constants now:** deferred; the parser does not expose
  them.
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
sees `DFDS` defaults supported by the current reader; it does not inspect
diagram constants, other data types, or runtime dataflow.

## References

- [Security analysis command and rule categories](0026-security-analysis-command-and-rules.md)
- [Typed default-data reader](0027-typed-default-data-reader.md)
- `pylabview/LVdatatype.py`: `TYPEDESC_FLAGS.HasLabel` and `parseRSRCDataFinish`

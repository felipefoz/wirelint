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

Reports VI string defaults that appear to contain a stored credential.

| Setting | Value |
| --- | --- |
| Default enablement | Enabled |
| Default severity | `warning` |
| CWE | CWE-798, CWE-259 |
| Applies to | VI-family resources (`.vi`, `.vit`, `.vim`) |
| Rule-specific options | None |

Each string default is checked with these heuristics, strongest first:

1. **Private keys and token formats.** PEM/PGP private-key headers, AWS
   access key IDs (`AKIA`/`ASIA`), GitHub, GitLab, Slack, Google API, and
   Stripe live keys, and signed JSON Web Tokens. These match anywhere in the
   text, without a key name.
2. **Credential-named controls.** The default of a control or indicator
   whose label names a credential, such as `Password`, `DB Password`,
   `API Key`, `access_token`, `Client Secret`, or `Kennwort`. For cluster and
   array members, the innermost labeled level decides.
3. **Credential assignments in text.** A credential-named key followed by a
   value: `password=...`, `pwd: ...`, `"api_key": "..."`, `token := ...`,
   `secret => ...`, `<password>...</password>`, `scheme://user:pass@host`,
   and `Authorization: Bearer ...`.

Names are split into words at punctuation and camel-case boundaries. A name
counts as a credential when a word ends in a credential term (`password`,
`passwd`, `pwd`, `passphrase`, `passcode`, `secret`, `token`, `credential`,
`apikey`, ...) or when `key` follows a qualifier such as `api`, `access`,
`private`, `secret`, or `encryption`. Names that describe credential
metadata are ignored, for example `Password Hint`, `Password Length`,
`Token URL`, `Token Type`, or `Secret Name`. A bare `Key` or `Pass` is not a
credential name.

For heuristics 2 and 3, values are ignored when, after trimming, they are
shorter than four characters, consist of one repeated character (`****`),
are common placeholders (`changeme`, `example`, `none`, `true`, ...),
reference a variable or template (`$NAME`, `${NAME}`, `$(NAME)`, `%NAME%`,
`{{name}}`, `<name>`, `[name]`, `your_...`), repeat a credential word
(`password`, `token`), read like user instructions (`Enter password here`), or
read like a message: text with spaces that ends in `.`, `!`, or `?`, or that
mentions a credential term (`The password is incorrect!`).

The finding names where the first match was found, using the control's labels
(for example `"Settings" > "DB Password"`) or its type entry when no
label is stored, together with the heuristic that matched. It counts any other
matching defaults in the file. The message never includes a stored value.
Findings are review signals, not confirmation of exploitability. Remove the
credential or load it from an appropriate secret store at runtime.

The rule reads the default values that front-panel controls store in the VI's
source, for VIs saved with or without separate compiled code. It uses each
control's front-panel name when available, falling back to its type descriptor
label. Nested values use their type descriptor labels. A control whose data type
the reader does not support is skipped. It does not inspect block-diagram string
constants, the front panel's "Password Display" setting, or secrets stored in
other data types. Secrets without a recognized name or format are not
reported.

Rule suppression directives are shared across commands. Their syntax and
limitations are documented in the
[quality and hygiene rule reference](quality-rules.md#skipping-a-rule-with-a-bookmark).

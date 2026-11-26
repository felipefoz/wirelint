# Security analysis rules

Security rules run with `wirelint security` and are listed separately from the
quality and source-control hygiene rules used by `wirelint lint`. They read
stored facts from LabVIEW files. The System Exec rule follows a limited set
of local block-diagram connections.
Findings are review signals, not confirmation of exploitability.

All security rules are enabled by default and use the shared `enabled` and
`severity` options. Configure them under `security.rules` in the
[configuration template](../wirelint.example.yaml), and see the
[configuration guide](configuration.md) for schema and exit-threshold details.

## Rules

- [hardcoded-secret-default](#hardcoded-secret-default)
- [system-exec-command-input](#system-exec-command-input)

## `hardcoded-secret-default`

Reports VI string defaults and scalar block-diagram string constants that
appear to contain a stored credential.

| Setting | Value |
| --- | --- |
| Default enablement | Enabled |
| Default severity | `warning` |
| CWE | CWE-798, CWE-259 |
| Applies to | VI-family resources (`.vi`, `.vit`, `.vim`) |
| Rule-specific options | None |

Each string is checked with these heuristics, strongest first:

1. **Private keys and token formats.** PEM/PGP private-key headers, AWS
   access key IDs (`AKIA`/`ASIA`), GitHub, GitLab, Slack, Google API, and
   Stripe live keys, and signed JSON Web Tokens. These match anywhere in the
   text, without a key name.
2. **Credential-named values.** A constant or a control/indicator default
   whose label names a credential, such as `Password`, `DB Password`, `API Key`,
   `access_token`, `Client Secret`, or `Kennwort`. For cluster and array
   defaults, the innermost labeled level decides.
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

The finding names where the first match was found, using a constant's label,
the control's labels (for example `"Settings" > "DB Password"`), or its type
entry when no label is stored, together with the heuristic that matched. It
counts other matching strings in the file. The message never includes a stored value.
Findings are review signals, not confirmation of exploitability. Remove the
credential or load it from an appropriate secret store at runtime.

The rule reads the default values that front-panel controls store in the VI's
source, for VIs saved with or without separate compiled code. It uses each
control's front-panel name when available, falling back to its type descriptor
label. Nested values use their type descriptor labels. A control whose data type
the reader does not support is skipped. Scalar block-diagram string constants
with `stdString` display objects are read from the `BDHb` source heap,
including those in nested diagrams.
String values inside composite diagram constants are not inspected. A string
constant with missing or malformed saved data produces an analysis error;
without a block-diagram source heap there are no diagram constants to inspect.
The rule does not inspect the front panel's "Password Display" setting or
secrets stored in other data types. Secrets without a recognized name or
format are not reported.

Rule suppression directives are shared across commands. Their syntax and
limitations are documented in the
[quality and hygiene rule reference](quality-rules.md#skipping-a-rule-with-a-bookmark).

## `system-exec-command-input`

Reports front-panel control influence on the command line of NI's
`System Exec.vi`, directly or through Concatenate Strings.

| Setting | Value |
| --- | --- |
| Default enablement | Enabled |
| Default severity | `warning` |
| CWE | CWE-78, CWE-88 |
| Applies to | VI-family resources (`.vi`, `.vit`, `.vim`) |
| Rule-specific options | None |

A call alone is not reported. Constant-only command construction, unrelated
controls, controls connected only to standard input and unwired command
inputs do not produce this warning. Concatenation does not sanitize a value.
Findings do not repeat command strings or control defaults.

Review who can influence the control, the executable being invoked, shell
use and argument parsing on the target operating system. Prefer a fixed
executable and allowlisted argument choices. The warning is not proof of
an exploitable vulnerability, and constant commands are not certified safe.

The rule resolves static calls through modern `LIbd/IUVI` links (saved
LabVIEW 14.0 or newer) and reads version-b diagram source heaps. It does not
load the referenced NI library or execute a command. A custom VI with the
same basename outside NI's platform library does not match.

Supported sources are front-panel controls and diagram constants; the
supported transfer operation is Concatenate Strings. Other subVIs,
primitives, format functions, structure tunnels, variables, property nodes
and dynamic calls are not traced. Network/file input is not classified as
a source in this version. No sanitizer recognition is implemented.

For recognized calls, an unsupported or ambiguous command path produces an
analysis error and exit status 2, even with `--fail-on none`. Missing source
also produces an error when a matching call link exists. Unsupported link
record kinds are errors because they cannot be reliably skipped; this can
affect files without a known System Exec call. No matching static call link
means no finding, not a security guarantee.

Disable the rule through YAML if its current format coverage is unsuitable:

```yaml
rules:
  system-exec-command-input:
    enabled: false
```

An unlinked `#wirelint-ignore system-exec-command-input` diagram directive
suppresses this rule's findings for the file. Attach the comment arrow to one
System Exec call node to suppress only that call's finding. An arrow to an input
control does not suppress downstream calls. Command-path extraction still runs;
neither form hides incomplete-analysis errors. See
[object-scoped ignores](quality-rules.md#ignoring-one-object-with-a-comment-arrow).

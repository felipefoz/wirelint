# HTTP client security and shared call dataflow

- Status: Accepted
- Date: 2026-11-26

## Context

An HTTP request is not inherently a vulnerability. A control-influenced
destination can require SSRF review, a non-HTTPS URL can expose traffic, and
disabling server verification can defeat TLS authentication. These are
distinct concerns: `OpenHandle.vi`'s `verify server` input defaults to true;
false disables verification, but does not establish a plaintext request.
The installed LabVIEW 2024 VI descriptions also say client handles are optional
for independent requests. They do not establish that an unwired handle forces
HTTPS.

System Exec already needs static call identity, graph connectivity, and
local string influence. Putting each new rule's interpretation in the format
reader would mix rule policy with binary decoding and duplicate traversal.

## Decision

- Share one decoded static call-link list and one lazily built diagram graph
  for active call-oriented checks. Keep generic input tracing, typed scalar
  constants and incomplete-path handling in the format/dataflow layer; keep
  NI callee matching, security decisions and tests together in each rule module.
  Store generic per-rule call evidence so ignores and errors can use the same
  handling. Existing System Exec behavior and its call identities remain.
- Add `http-control-url` (CWE-918), `http-plaintext-url` (CWE-319), and
  `http-server-verification` (CWE-295), enabled at warning severity.
  Findings request review and do not claim a reachable or exploitable call.
- Identify NI `LabVIEWHTTPClient.lvlib` by qualified name and `vi.lib`
  `httpClient` path. Request calls include GET, HEAD, DELETE, POST, PUT and
  the file, buffer and multipart variants. Read request URL slot 5 and
  OpenHandle/ConfigSSL verification slot 12. The installed LabVIEW 2024 VIs
  document these connector indices and defaults; saved project-owned GET, POST,
  PUT and verification callers validate their persisted call links and wiring.
- Treat direct or Concatenate Strings control influence as a destination
  review. Flag direct literal URLs without an explicit case-insensitive
  `https://` prefix; also flag control-influenced URLs because their scheme
  is not established. Do not equate that review signal with proven plaintext.
- Recognize directly wired Boolean false on either verification input.
  An unwired input uses the documented true default. Dynamic values, malformed
  constants and unsupported paths are incomplete analysis, not safe values.
  Literal-only URL concatenation is also incomplete until its ordering and
  value are supported. A true setting or HTTPS URL is not a security guarantee.
- Saved scalar `ConstValue` data is retained in the graph by its DCO UID.
  Decode only direct scalar string and Boolean display objects; validate
  flattened lengths and Boolean representations. Do not disclose values.
  Incomplete analysis is reported even when findings are suppressed.
- A linked ignore targets the call node, not its inputs; file-wide ignores
  remain available. Neither form suppresses errors. Use the existing rule
  registry, severity configuration, reports and one-finding-per-file model.

## Alternatives

- Warn on all HTTP calls: rejected because an ordinary request is not
  evidence of an insecure destination or TLS configuration.
- Infer plaintext from disabled verification: rejected because verification
  and transport encryption are different properties.
- Assume dynamic or unsupported values are safe: rejected because it hides
  incomplete analysis. Conservatively review control-influenced schemes.
- Decode or execute VIs using LabVIEW during scanning: rejected to retain
  platform independence and avoid runtime side effects.

## Consequences

Checks are local and do not follow subVI bodies, network input, structure
tunnels, redirects, variables, sanitizers or handle reconfiguration. A false
guard does not suppress a finding because execution reachability is not
modeled. Older or unsupported link layouts can still cause analysis errors.
No new dependency is required; scans remain independent of LabVIEW.

Fixtures use constant-false guarded calls. Their guard was inspected before
execution during creation; the HTTP calls themselves were not executed.
Running the scanner never runs fixture VIs.

## References

- [Format research and attribution](0001-project-identity-and-format-references.md)
- [Windows and Linux compatibility](0002-windows-linux-compatibility.md)
- [Structural graph reader](0036-diagram-graph-reader.md)
- [System Exec input analysis](0037-system-exec-command-input.md)
- [Object-scoped ignores](0040-object-scoped-bookmark-suppression.md)
- `pylabview/LVheap.py`: saved Boolean and string objects and `ConstValue`.
- Installed LabVIEW 2024 `vi.lib/httpClient` VI and terminal descriptions.

# Configuration initialization and display

- Status: Accepted
- Date: 2026-11-26

## Context

Users need a starting configuration and a way to inspect defaults together
with their overrides without scanning files.

## Decision

- `config init <FILE>` writes the packaged example to a new file, using
  exclusive creation to avoid overwriting existing files.
- `config show [FILE]` validates an optional file and prints effective YAML
  for both rule registries. Without a file, it prints built-in defaults.
- Legacy rule overrides appear under their inferred category. Rule options
  with no effective restriction are omitted.

## Alternatives

- Print only the input file: this would hide defaults and offer little beyond
  reading the file directly.
- Generate a minimal file on initialization: the full example explains the
  available options and provides a starting point for editing.

## Consequences

The initialized example includes exclusions and a connector pane restriction
that are not built-in defaults. Displayed YAML reflects analysis defaults,
including the special handling of maximum-only saved-version bounds.

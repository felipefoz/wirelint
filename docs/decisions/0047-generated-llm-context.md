# Generated LLM context

- Status: Accepted
- Date: 2026-11-26

## Context

Agents can use a compact entry point to discover project information and Rust
source details. The files should be generated locally rather than sending
repository contents to a hosted service.

## Decision

Generate root-level `llms.txt` and `llms-full.txt` with the released
`cargo-llms-txt` 0.1.1 Cargo subcommand. Regenerate them when Rust sources,
`Cargo.toml`, or the README change. The tool is installed separately and is
not a WireLint runtime dependency.

## Alternatives

- A custom generator would give tighter control over output and reproducibility
  but add code to maintain.
- Documentation-site generators focus on published pages rather than Rust
  source, and may not produce valid links to repository Markdown files.
- The published `llmstxt-gen` Python package does not support Rust; its
  unreleased Rust parser produced an incorrect dependency graph in a trial.

## Consequences

The files summarize source-derived items, not necessarily a public crate API;
read the source and user guides for authoritative behavior. The generator
includes timestamps and uses platform-specific paths and filesystem ordering,
so byte-for-byte regeneration is not stable. Review generated changes and do
not enforce a byte-for-byte freshness check in CI.

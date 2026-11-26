# Agent instructions

- Keep changes focused and follow existing Rust style.
- Add focused tests for every new feature.
- Add one or more representative fixtures in `tests/fixtures/quality/<rule-id>/` or `tests/fixtures/sast/<rule-id>/` for every new rule, including any configuration needed to exercise it.
- When validating changes, run both `cargo run -- lint tests/fixtures --verbose --fail-on none` and `cargo run -- security tests/fixtures --verbose --fail-on none`; inspect findings and ensure there are no analysis errors. Use a fixture-specific configuration when a rule requires one.
- Add concise module-level documentation and function doc comments that explain purpose, contracts, relevant errors, and invariants without restating obvious code.
- Run `cargo fmt --check` and `cargo test` for Rust changes.
- Run `cargo clippy --all-targets --all-features -- -D warnings` when practical.
- Use Conventional Commits for commit subjects: `<type>[optional scope]: <summary>`.
- Keep the project compatible with Windows and Linux. Follow `docs/decisions/0002-windows-linux-compatibility.md`, avoid platform-specific assumptions, and validate platform-sensitive changes on both when possible.
- Avoid adding dependencies unless they are needed; explain why when you do.
- Read relevant `docs/` decision records before design or implementation work.
- For VI/RSRC binary-format work, consult the references and attribution guidance in `docs/decisions/0001-project-identity-and-format-references.md`. Before researching, make sure a local clone of each reference repo exists under the untracked `.reference-repos/` folder at the project root (one subfolder per repo, e.g. `.reference-repos/pylabview`); clone any that are missing and run `git pull --ff-only` in each that already exists so research uses current upstream sources. Search and read these local clones instead of fetching the same files repeatedly over the network. These clones are local research aids only, never a WireLint dependency or vendored code source; attribution rules in decision 0001 still apply to anything consulted this way.
- Keep user documentation in `docs/user-guide/`, separate from decision records. Keep the README focused on the overview, quick start, and links to user docs.
- Consult `llms.txt` for a project overview and `llms-full.txt` for generated source details when useful. Verify behavior against the source and user documentation.
- After changes to Rust sources, `Cargo.toml`, or `README.md`, regenerate `llms.txt` and `llms-full.txt` with `cargo llms-txt`. Install the generator with `cargo install cargo-llms-txt --version 0.1.1 --locked` if needed. Review the output; timestamps and platform-specific paths can change on each run.
- When CLI behavior changes, update its `--help` text, relevant user documentation, and tests in the same change. Use Clap to derive help from CLI definitions; decision records explain rationale, not usage.
- Record every project, design, or architecture decision in `docs/`, including context, alternatives, and consequences.

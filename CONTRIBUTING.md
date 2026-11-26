# Contributing

Thanks for your interest in contributing to WireLint.

## Development setup

Install the stable Rust toolchain using [rustup](https://rustup.rs/), then confirm `rustc` and `cargo` are available:

```text
rustc --version
cargo --version
```

### Windows build tools

The default `x86_64-pc-windows-msvc` Rust target requires Microsoft's C++ build tools; Rustup does not install the MSVC linker or Windows SDK. Install the Build Tools bootstrapper with winget:

```powershell
winget install -e --id Microsoft.VisualStudio.BuildTools
```

The bootstrapper does not install the compiler toolchain by itself. After it finishes:

1. Open Visual Studio Installer and modify the Build Tools installation.
2. Select the **Desktop development with C++** workload.
3. Ensure the MSVC v143 build tools and a Windows 10/11 SDK are selected.
4. Apply the changes, then build from a Developer PowerShell or Developer Command Prompt.

## Build and checks

Run the relevant checks before submitting changes:

```text
cargo fmt --check
cargo test
cargo clippy --all-targets --all-features -- -D warnings
```

Add focused tests for new features and bug fixes.

Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

Tests must run from a clean checkout without LabVIEW or ignored sandbox files.
Construct binary fixtures synthetically; shared fixture builders belong in
`tests/support/`. Keep XML fixtures inline when they are small.

## Commit messages

Use Conventional Commits for commit subjects:

```text
<type>[optional scope]: <summary>
```

For example: `feat(parser): add VI resource parsing`.

## Platform compatibility

WireLint targets both Windows and Linux. Prefer cross-platform Rust APIs, avoid assumptions about path separators, shells, or filesystem behavior, and isolate platform-specific code when it is unavoidable. For platform-sensitive changes, test on both operating systems when possible and state which platforms were validated.

## Design and documentation

Read relevant decision records in `docs/` before making design or architecture changes. Record new project, design, or architecture decisions in `docs/`, including context, alternatives considered, and consequences.

Keep changes focused and document user-visible behavior changes.

## Releases and installers

[cargo-dist](https://axodotdev.github.io/cargo-dist/) manages the GitHub release
workflow, archives, checksums, and Windows MSI. A
[`cargo-deb` build hook](packaging/build-deb.sh) adds the Debian package through
cargo-dist's `extra-artifacts` setting. Packages are published only to GitHub
Releases; no package registry credentials are needed.

[git-cliff](https://git-cliff.org/), configured in `cliff.toml`, generates
`CHANGELOG.md` from Conventional Commits. cargo-dist reads the version section
matching the pushed tag out of that file and uses it as the GitHub Release body.

### Prepare a release

1. Update `[package].version` in `Cargo.toml`. Use a stable `major.minor.patch`
   version representable by MSI: major and minor at most 255, patch at most
   65535.
2. Run `cargo check` to update the root package version in `Cargo.lock`.
   Do not use `cargo update` just to bump the project version; it can also
   update dependencies.
3. Run the normal checks above and `dist plan --tag v<version>` using the pinned
   cargo-dist version. Review and commit the version changes, then push them
   to `main`.

Pushing a `Cargo.toml` change to `main` triggers
`.github/workflows/prepare-release.yml`, which reads the new version, and,
if a matching tag doesn't already exist, regenerates `CHANGELOG.md` with
git-cliff, commits it, and pushes the `v<version>` tag. That tag push triggers
the cargo-dist release workflow exactly as a manually pushed tag would: it
checks that the tag selects the Cargo package version, runs formatting, tests,
and Clippy on Windows and Linux, builds the packages, and publishes them with
checksums. Cargo commands use `--locked` in our build hook and checks to
prevent dependency resolution during those steps.

Maintainers still own the version bump; CI never changes `[package].version`.
Pushing a `Cargo.toml` change that doesn't alter the version (e.g. a dependency
bump) is a no-op for `prepare-release.yml`, since the tag it would create
already exists.

`prepare-release.yml` pushes using a `RELEASE_PAT` repository secret (a
fine-grained PAT scoped to this repo with Contents: Read and write) instead of
the default `GITHUB_TOKEN`, because GitHub does not let `GITHUB_TOKEN`-authored
pushes trigger other workflows, and the pushed tag needs to trigger the release
workflow.

Pull requests build release artifacts too, including the Debian package's
extraction smoke test, but do not publish a release. This is intentionally more
expensive than cargo-dist's default plan-only PR mode.

### Maintain packaging

Install the version pinned in `dist-workspace.toml`:

```text
cargo install cargo-dist --version 0.34.0 --locked
dist init --yes
dist generate --check
dist plan
```

Edit `dist-workspace.toml`, package metadata, or `.github/release-setup.yml`
and regenerate; do not hand-edit `.github/workflows/release.yml` or
`wix/main.wxs`. Keep the WiX upgrade and PATH GUIDs in `Cargo.toml` stable across
releases so upgrades refer to the same installed application.

On Windows, `dist build --artifacts local --target x86_64-pc-windows-msvc`
builds the MSI and ZIP. cargo-dist currently requires WiX 3, not modern WiX,
for this backend. Its generated CI uses the WiX 3 toolchain preinstalled on the
Windows 2022 runner. Do not request an older Chocolatey package revision:
Chocolatey treats that as a downgrade and fails. WiX 3 is out of support; follow
upstream support for a modern WiX backend when upgrading cargo-dist. No separate
custom installer implementation is maintained here.

On Debian/Ubuntu, `bash packaging/build-deb.sh` installs the pinned cargo-deb
tool, builds the package with the `dist` profile, and tests the extracted
executable and required notices without modifying the system installation.
It also generates the Debian package's separate SHA-256 checksum file.
Running `dist build --artifacts global` on Linux exercises the same hook as CI.
Local builds require Rust, a C toolchain, and Debian packaging tools.

The release workflow needs GitHub Actions enabled and permission for its
`GITHUB_TOKEN` to write repository contents. Review failed workflow runs before
retrying; never move a published release tag to different source code.

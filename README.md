# WireLint

[![CI](https://img.shields.io/github/actions/workflow/status/felipefoz/wire-lint/ci.yml?branch=main&label=CI)](https://github.com/felipefoz/wire-lint/actions/workflows/ci.yml)
![Language: Rust](https://img.shields.io/badge/language-Rust-orange)
![Status: Beta](https://img.shields.io/badge/status-beta-yellow)
![Platforms](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-green)

![WireLint: LabVIEW static analysis](docs/assets/wirelint-hero.svg)

Static Analysis for LabVIEW.

WireLint aims to provide an independent static-analysis tool for LabVIEW files, similar in purpose to NI's VI Analyzer. It is not affiliated with, endorsed by, or sponsored by National Instruments (NI). LabVIEW is a trademark of NI.

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and contribution guidelines.

WireLint is licensed under the MIT License. See [LICENSE](LICENSE).

## Documentation

- [Changelog](CHANGELOG.md)
- [Install from GitHub Releases](docs/user-guide/installation.md)
- [Getting started and CLI usage](docs/user-guide/cli.md)
- [Rule configuration](docs/user-guide/configuration.md)
- [Quality and hygiene rules](docs/user-guide/quality-rules.md)
- [Security analysis rules](docs/user-guide/sast-rules.md)
- [GitLab and GitHub code quality reports](docs/user-guide/ci-reports.md)
- [Configuration template](docs/wirelint.example.yaml)
- [SAST configuration template](docs/wirelint-sast.example.yaml)
- [Project roadmap](docs/roadmap.md)

## Security analysis

Run `wirelint sast <folder>` to find credential-like assignments in VI string
defaults. See the [security rules](docs/user-guide/sast-rules.md) and [SAST
configuration template](docs/wirelint-sast.example.yaml).

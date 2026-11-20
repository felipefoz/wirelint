# Installation

Download packages from [GitHub Releases](https://github.com/felipefoz/wire-lint/releases).
Installers are provided for x64 Windows and x86_64 Debian/Ubuntu Linux. Rust and
LabVIEW are not required to run WireLint.

## Windows

Download and run `wirelint-x86_64-pc-windows-msvc.msi`. It installs for the
current user under `%LOCALAPPDATA%\Programs\wirelint`, does not require
administrator access, offers an installation directory, and adds its `bin`
directory to that user's PATH. Open a new terminal afterwards:

```powershell
wirelint --version
wirelint --help
```

Installing a newer MSI upgrades that user's existing installation. Because the
MSI has changed from per-system to per-user, uninstall an older per-system
installation first. Remove WireLint through Windows Settings > Apps > Installed
apps. A per-system installation is not currently provided.

The MSI is currently unsigned; Windows may display an unknown-publisher warning.
Use only files downloaded from this repository's releases and verify their
checksums.

## Debian and Ubuntu

Download `wirelint_amd64.deb`, then run this command from the download directory:

```sh
sudo apt install ./wirelint_amd64.deb
wirelint --version
wirelint --help
```

The package installs the executable on PATH and its documentation under the
system documentation directory. Upgrade by downloading and installing the
package from a newer release. To remove it:

```sh
sudo apt remove wirelint
```

Packages are built on Ubuntu 22.04 and target that glibc baseline (2.35) or newer,
such as Debian 12 and Ubuntu 22.04 or later. An APT repository and automatic
updates are not provided.

## Checksums and portable archives

Each release includes a `sha256.sum` file for cargo-dist's standard artifacts
and a separate `wirelint_amd64.deb.sha256` file for the Debian package.
On Windows, compare the MSI's entry with the output of:

```powershell
Get-FileHash .\wirelint-x86_64-pc-windows-msvc.msi -Algorithm SHA256
```

On Linux, with the Debian package and its checksum file in the same directory:

```sh
sha256sum --check wirelint_amd64.deb.sha256
```

These hashes check file integrity, not publisher identity.

ZIP and tar archives are also available for portable use without an installer.
They include the executable, README, license, and third-party notices. The MSI
includes the executable and license; the Debian package also includes the
README and third-party notices.

See [CLI usage](cli.md) for scanning and configuration.

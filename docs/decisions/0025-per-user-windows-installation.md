# Per-user Windows installation

- Status: Accepted
- Date: 2026-11-20

## Context

The Windows MSI initially installs under Program Files and adds its location
to the system PATH, requiring administrator privileges. WireLint should be
installable by a user without elevated privileges.

## Decision

Make the Windows MSI per-user only. Install by default under
`%LOCALAPPDATA%\Programs\wirelint` and add the executable's `bin` directory to
the installing user's PATH. Do not offer a per-system install option initially.

## Alternatives

- Keep the per-system MSI, which requires administrator privileges.
- Offer a per-user/per-system choice, which adds installer UI and two install
  contexts to maintain.

## Consequences

- Installing and updating WireLint does not require administrator privileges,
  and only affects the installing user.
- Users who need WireLint available to all accounts must use another
  deployment approach until a per-system option is added.
- MSI upgrades apply within the same per-user installation context. Existing
  per-system installations may need to be removed before installing the
  per-user MSI.

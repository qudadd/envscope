# Code signing policy

[Project home](README.md) · [Downloads](https://github.com/qudadd/envscope/releases) · [Privacy](PRIVACY.md) · [Uninstall](docs/UNINSTALL.md)

Last reviewed: **2026-10-31**.

## Current status

EnvScope is preparing an application for free Windows code signing from the
[SignPath Foundation](https://signpath.org/). **The project has not been accepted
and does not currently receive signing services from the Foundation.**

The published **0.25.0 Alpha** Windows executables are unsigned. macOS packages
use ad-hoc signing, without Developer ID signing or Apple notarization. File
checksums, application identity checks and successful CI runs do not establish
a trusted publisher signature. The current release remains available with
these limitations explicitly disclosed.

## People and approval

The current maintainer is [qudadd](https://github.com/qudadd), who performs the
author, reviewer and release-approver roles. This is a single-maintainer project;
these roles do not imply an independent second reviewer. The maintainer has
confirmed that GitHub two-factor authentication is enabled.

If the Foundation accepts the project, all repository and signing-service
members must use multi-factor authentication. Signing-service access and its
MFA have not yet been provisioned. Each signing request will require manual
approval by an authorized maintainer after reviewing its source revision,
build result and artifact scope. Changes to maintainers or signing permissions
must be reflected here.

## Builds and signing scope

The repository publishes its [desktop build workflow](.github/workflows/desktop.yml),
[checks workflow](.github/workflows/checks.yml), tagged source and release
checksums. Windows and macOS packages are built with GitHub Actions. This is
source-linked build evidence, not a claim of bit-for-bit reproducibility.

The proposed Windows signing scope is EnvScope's own executable and native
timezone helper built from this repository. Bundled third-party source,
libraries and tools retain their upstream attribution and licenses, documented
in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). We will not submit unrelated
upstream executables for signing as if they were authored by EnvScope. The
Foundation must review the packaging and diagnostic scope before any signing
integration is enabled.

Approved signing would be integrated into the controlled build before final
archives and checksums are generated. Publisher verification and update checks
also require implementation and validation; publishing this policy does not
activate them. See the remaining work in the [signing guide](docs/SIGNING.md).

If accepted, the public policy and download pages will identify the signing
service actually used and credit the Foundation. Its certificates identify
**SignPath Foundation**, and use remains subject to its
[Code of Conduct](https://signpath.org/terms), including revocation. No current
binary should be described as signed by the Foundation.

## Users and project conduct

Diagnostics are read-only. Repairs, account-profile operations and persistent
maintenance require separate review of their effects and explicit confirmation.
The project provides local diagnostics and configuration management, not
accounts, proxy subscriptions, forged device identities or an assurance of
service eligibility. Its network and proxy-configuration checks are disclosed
for the Foundation's eligibility review.

External requests, local data and user controls are described in the
[privacy notice](PRIVACY.md). Users can stop scheduled components and remove
the application using the [uninstall guide](docs/UNINSTALL.md). Report a
suspected compromised release through the channels in [SECURITY.md](SECURITY.md);
do not include credentials or private diagnostic files in a public issue.

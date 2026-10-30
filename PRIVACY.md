# Privacy notice

本说明介绍 EnvScope 读取什么、何时联网、如何保存及移除本地资料。当前软件没有 EnvScope 运营的上传服务器或分析统计服务。

Applies to EnvScope **0.25.0 Alpha**. Last reviewed: **2026-10-31**.

## Local processing

EnvScope is an open-source Windows and macOS application maintained at
[qudadd/envscope](https://github.com/qudadd/envscope). It has no project-operated
backend, analytics SDK or automatic diagnostic-report upload. The desktop
interface communicates with its own loopback service. Opening a GitHub issue,
following an external link or using a third-party client involves that service
separately.

Depending on selected checks, EnvScope reads operating-system and application
versions, timezone and locale, selected client settings, DNS and network-route
metadata, proxy configuration, process metadata, disk availability and network
test results. Some checks may be unavailable without OS authorization. Native
diagnostics do not change settings. Repairs and persistent maintenance have
their own effect preview and confirmation.

Account operations are separate from diagnostics. When explicitly authorized,
they copy or exchange local Claude profile directories, which can contain
cookies, login credentials, identity files and other private state. They do not
upload these copies to EnvScope. OS credential stores are not fully included in
these copies. See [account data and recovery](docs/ACCOUNT_VOLUMES.md).

## Requests to external services

Network tests start when the user requests detection, uses a relevant tool, or
enables a maintenance plan that includes those tests. Online command-line probes
require `--online`; native UDP STUN additionally requires `--stun`.

**The desktop application checks GitHub for software updates by default**, at
startup and periodically while running. This can be disabled in the software
update/background settings. Downloading, installing or restarting into a new
version requires confirmation. Checking for updates is separate from consent
to run diagnostics or maintenance.

These requests disclose the source IP seen by the recipient and normal request
metadata, such as time, requested host/path and user agent. DNS queries are also
visible to the resolver handling them. Proxy or VPN use may change the source
seen by a destination; it does not make the requests anonymous.

| Service | Purpose and data sent | Provider information |
|---|---|---|
| Cloudflare | HTTP connection/public-IP observations and UDP STUN; network request metadata | [Privacy policy](https://www.cloudflare.com/privacypolicy/) |
| ipify | IPv4/IPv6 public-IP observations; network request metadata | [API provider website](https://www.ipify.org/) |
| IPinfo | Requested IP-region suggestions and network/ASN information; network request metadata | [Privacy policy](https://ipinfo.io/privacy-policy) |
| Google STUN | Optional native UDP and browser ICE observations; STUN request metadata | [Privacy policy](https://policies.google.com/privacy) |
| Anthropic / Claude | Anonymous service-response checks; network request metadata | [Privacy policy](https://www.anthropic.com/legal/privacy) |
| GitHub | Release/upstream-version checks and requested downloads; requested repository paths and application user agent | [Privacy statement](https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement) |
| Optional ecosystem endpoints | Anonymous reachability requests to Cloudflare, Datadog, Segment/Twilio, Stripe and Intercom domains | [Datadog](https://www.datadoghq.com/legal/privacy/), [Twilio](https://www.twilio.com/en-us/legal/privacy), [Stripe](https://stripe.com/privacy), [Intercom](https://www.intercom.com/legal/privacy) |

The ipify API homepage is linked as provider information, not as a verified
separate privacy-policy page. Third-party policies and retention practices are
controlled by those providers.

HTTP diagnostic probes do not attach Claude login credentials, browser cookies
or profile files. Ecosystem checks are reachability requests; EnvScope does not
embed those services' analytics SDKs. Browser observations are returned to the
local EnvScope process. A user-specified proxy may receive its supplied proxy
credentials and network requests; custom command-line targets contact the
destinations selected by the operator.

Optional temporary browser sessions run an installed browser with a separate
profile. Websites the user visits receive ordinary browser traffic; they are
not covered by a promise of anonymity. Explicit upstream installation/update
tools also have their own behavior and permissions, disclosed separately.

## Files, retention and sharing

Application preferences, recent diagnostic history, recovery backups, update
packages, browser-session records and maintenance logs are normally stored
under `~/.envscope` in the current user's home directory. Account slots and
some upstream-compatible state use `~/.claude-switcher`. Separately authorized
privileged timezone services store their protected state at the fixed system
paths listed in the [timezone service guide](docs/TIMEZONE_SERVICE.md).

Normal diagnostic history keeps the latest 50 redacted records. A local random
HMAC key enables address-change comparison without saving plain addresses in
that comparison record. This is not complete anonymization: system details and
user-entered settings, such as permitted address ranges, can still identify the
environment. Operators can explicitly request sensitive local CLI output with
`--include-sensitive`. Daily event logs and recovery backups are retained for
review and recovery; they are not all automatically deleted with old history.

**Original configuration backups and directory-based account copies are not
encrypted and may contain secrets.** They are excluded from normal diagnostic
exports. Optional encrypted account archives have their own password and format
requirements; they do not encrypt every application file. Temporary browser
cleanup removes eligible files after the authorized session closes, but failed
cleanup retains data for a later retry. Deletion is not guaranteed secure erasure.

Diagnostic reports and support bundles use best-effort redaction, not a guarantee
that all sensitive information has been removed. Review every file before
sharing it. Do not upload account slots, raw backups, browser profiles, tokens
or proxy credentials to a public issue.

## Your controls and contact

You can choose applicable tests, turn off automatic update checks, decline a
repair, and disable approved maintenance. User maintenance, the optional process
guard and the privileged timezone service are separate components; closing the
window does not disable them. See [uninstall and data removal](docs/UNINSTALL.md)
for stopping them, restoring supported changes and removing local files.

Privacy questions can be raised with the maintainer through the project's
[issues](https://github.com/qudadd/envscope/issues) without including private
data. For security-sensitive reports, follow [SECURITY.md](SECURITY.md). The
project has no central copy from which to retrieve or delete your local data.
This notice is versioned in the public repository and should be updated when
data handling changes.

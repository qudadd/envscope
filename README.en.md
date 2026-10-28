# EnvScope

![EnvScope desktop interface, offline demonstration](docs/images/desktop.png)

A minimal Windows/macOS Claude environment toolkit. Alpha v0.8.0.

The desktop package now uses an independent native window and a tray/menu-bar
entry. Closing can keep it in the background; launching twice activates the
existing window. Official software updates require confirmation, matching
release and GitHub SHA256 digests, safe side-by-side installation and a confirmed
restart. Upstream component changes are reviewed before inclusion, not executed
automatically. See [desktop acceptance](docs/DESKTOP_ACCEPTANCE.md).

Basic-use assessment distinguishes confirmed problems, explicit permission
denials, incomplete probes, inapplicable checks and unimplemented capabilities.
The strict privacy decision and account launch gate are unchanged. The Models
API probe now uses GET; native HTTP probes respect a discovered system HTTP
proxy when HTTPS/ALL proxy environment settings are absent.

This usability release adds a searchable, always-visible 32-check catalog,
inline native information panels, desktop account guidance, visible-page
keepalive and explicit disconnected-tab recovery. It preserves the original
macOS detailed readers as separate maintenance actions. See the
[task-based acceptance record](docs/USABILITY_TESTING.md).

The main workflow now includes reviewed desktop launch and graceful restart.
Each launch repeats native checks, including installation, desktop JSON, account
recovery state and the separate Claude web endpoint. Restart requests a normal
exit and rechecks again before opening; it never escalates to forced termination
or exchanges profiles. Readiness is not authentication or a privacy guarantee.
See the [product acceptance scope](docs/PRODUCT_ACCEPTANCE.md).

One click now checks the environment and automatically prepares a combined setup
and repair preview. One confirmation backs up, applies and rechecks. Optional Code
setup works even without a diagnosed fault: verified local HTTP(S) proxy, target
bypass cleanup and TLS verification. The selected proxy is tested again before
any file write. Custom/cloud providers and unselected remote proxies are not
rerouted. File receipts are freshly read, never treated as process or account
proof. Identical values are not rewritten for formatting. Upkeep preview, enable
and stop are available on the same page.

First launch offers a skippable three-step lesson, persisted locally across
restarts and replayable from the sidebar. Results prioritize one actionable
problem, followed by an actual trial in the user's Claude and optional upkeep.
All 14 baseline and 18 extended checks remain available; plain-language
explanations replace the default technical table. Symptom-based help covers
connection, login, interruptions, certificates, Code installation and MCP.
Manual confirmation of a reply never changes a measured verdict. Open-source
tool guidance distinguishes the bundled claude-switcher, the read-only Mihomo
interface and the separately installed Clash Verge Rev client.

Each of the 14 upstream Claude checks now has an observation, measurement scope,
remedy and upkeep plan. Reviewed user-scoped Windows tasks / macOS LaunchAgents
can run native checks every 5, 15 or 60 minutes. Optional Code config recovery
preserves unrelated current settings, makes private backups and pauses repeated
rewrites. Undo verifies hashes across restarts. Browser ICE and account login are
never inferred from scheduled native checks. Frozen package CI now adds real OS
registration, two automatic no-side-effect worker executions and removal on
Windows and both Mac architectures. Evidence is attached to each run; this does
not certify user permissions, login transitions, sleep/resume or real networking.
See [the source-mapped checklist and upkeep implementation](docs/CLAUDE_CHECKS.md).

The page explains specific problems, observations, causes and ordered next steps
without requiring raw JSON. A reviewed solution plan can repair deterministic
trailing commas, verify and set a local HTTP(S) proxy for Claude Code, remove
matching Code bypass entries and restore Code TLS verification. Original files
are backed up before atomic replacement. Fresh audits distinguish confirmed
resolution from missing evidence; hash-verified undo across restarts preserves later edits.

Backups in `~/.envscope/config-backups` are unencrypted and can contain secrets.
They remain local, are excluded from diagnostic exports and survive exit. Plans
are short-lived and bound to the current native report; history/imported reports
cannot authorize writes. Other problems have fixed file/settings entries and
concrete instructions. Organization access, trusted enterprise CAs and remote
service failures require their respective owner.

[Desktop downloads](https://github.com/qudadd/envscope/releases): Windows x64,
macOS Apple Silicon and Intel. Alpha packages are not commercially signed/notarized.

Based on the complete pinned functionality of
[claude-switcher](https://github.com/YOURSJEYO/claude-switcher), with independent
measurements, guarded transactional accounts, diagnostics and maintenance.
Scrapling is used only for source research, never at runtime.

```sh
python -m envscope audit                           # offline inventory
python -m envscope audit --online --stun --ipv6    # explicit public probes
python -m envscope desktop                         # opens one-click desktop UI
```

Python 3.10+ and system curl for online CLI probes. No Python runtime packages.
The desktop UI has no third-party scripts. Windows and macOS are the target
platforms; mobile adaptation is deferred. Double-click the desktop app, then
click the single test button. Native and browser observations merge automatically.
Windows has been built and locally checked. Automated rules and packaging checks
pass on Windows, Linux and macOS; browser interaction checks also pass.
macOS apps are built for Apple Silicon and Intel. Real installation, account
sessions, maintenance permissions and Safari validation remain pending.

The six minimal pages cover diagnostics, upkeep, accounts, tools, history and settings.
One-click auditing includes 14 baseline categories and 18 additional checks, with
specific explanations, direct remedies and a before/after repair review.
Added checks cover system DNS and selected routes, hosts overrides, system/env
proxy differences and bypasses, configured loopback listeners, TUN/controller
configuration, TLS verification, DNS/TCP/TLS/TTFB timings, HTTPS-date clock
comparison, desktop/profile/config discovery, CLI entry/config conflicts, disk
capacity and account-transaction integrity. Each check states its limits.
Native additions include verified staged account copies and rollback, dynamic
slots and labels, fresh launch preflight, proxy discovery without port scanning,
explicit-proxy connectivity and timing, a 50-report redacted history with private
HMAC comparisons, support bundles and preference restoration. Windows adds
read-only CLI-path and device/font inventory; browser Canvas/WebGL information
is collected only when requested and stays in the page.

All 57 tracked upstream files are pinned and retained with their MIT license.
Fixed adapters expose installed upstream maintenance: installation, repair,
guard/routing setup, status/checks and core updates on both target platforms;
region/client changes, temporary browsers and encrypted DMGs on macOS.
Unsupported or missing commands are disabled. Installer launch means started,
not installed. Original reported results never become independent probe passes.
See the exact [platform matrix](docs/FEATURE_PARITY.md).

Detection is read-only. Account switching and installed-system actions require
separate explicit clicks and confirmation. Interrupted account transactions
preserve recovery copies and refuse new writes; automatic power-loss recovery
is not implemented. Directory backups are **unencrypted** and are not support
bundles. Local copying does not guarantee cross-OS or server-session migration.
Never use both account managers concurrently. Upstream updates affect only its
installed core; EnvScope has no whole-product automatic updater.

- A timeout, missing IPv6 response, mDNS candidate, or relay-only ICE result is
  **unknown**, never proof of protection.
- Native UDP STUN and browser WebRTC are separate measurements.
- IPv4 and IPv6 have separate allowlists. An unexpected address is a policy
  violation only when the allowed range was explicitly configured.
- 401, 403, 429, and server errors are reported distinctly.
- Imported upstream verdicts are not trusted. Imported browser snapshots must
  be raw, complete, and recent; they are user-supplied, unsigned observations.
- Reports redact addresses by default. Interface presence, Fake-IP, successful
  DoH, and a running proxy are not proof of a protected traffic path.

Authoritative DNS observation, per-process traffic correlation, and firewall
protection are not implemented in this release. The default privacy profile
therefore reports **incomplete**. The transport profile intentionally limits the
required scope to HTTP egress. No result is a zero-leak or account-safety promise.

Exit codes: 0 clear within configured scope; 1 explicit policy/target mismatch;
2 incomplete/review; 3 invalid input or unavailable local resource.

See the [Chinese README](README.md) for proxy settings, browser snapshot import,
private policies, reports, tests, and the implementation roadmap. Licensed under
MIT; origins and integration boundaries are in [third-party notices](THIRD_PARTY_NOTICES.md).

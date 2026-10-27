# EnvScope

A minimal Windows/macOS desktop environment toolkit. Alpha v0.1.0.

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
Windows has been built and locally checked. macOS inventory parsing has fixture
tests and an app-build workflow; real macOS and Safari validation is pending.

The five minimal pages cover diagnostics, accounts, tools, history and settings.
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

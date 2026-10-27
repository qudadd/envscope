# Security and privacy boundaries

## Reviewed configuration remedies

Diagnostics do not change system or client settings. A separate reviewed plan
requires explicit boolean confirmation. Native edits target only the fixed
desktop JSON and Code user-settings JSON. Deterministic trailing commas are
removed outside strings; ambiguous syntax, duplicate keys and nonstandard
numbers are not guessed. Code proxy edits require a successful anonymous API
response over a discovered credential-free loopback HTTP(S) proxy with TLS
verification. TLS checks are restored, never disabled.

Original files and recovery hashes are stored before replacement under
`~/.envscope/config-backups`. Backups are unencrypted and can contain credentials;
they are excluded from reports, support bundles and source control. Do not share
them. Windows protection also depends on the home-directory ACL. Writes use a
cross-process lock, link/reparse checks, content comparisons and atomic per-file
replacement. Multi-step operations can partially complete; backups are retained.

Plans expire, are single-use and bind to the current server-owned report. History
cannot authorize a repair. Undo is session-scoped and refuses to overwrite later
edits. Backups remain after exit for manual recovery; automatic crash recovery is
not implemented. Execution is separate from fresh verification: missing evidence
cannot become a resolved problem.

Native diagnostics are read-only. Separate, explicitly confirmed account and
maintenance operations can stop/launch Claude, exchange profile files, install
the original helpers, update its core and change networking or locale. Merely
opening EnvScope or clicking native detection does not perform those actions.
No native firewall enforcement is implemented. Process monitoring is not a
network kill switch.

## Measurement limits

- Each observation applies only to its named endpoint, address family, transport,
  time, and client context. Curl, native UDP, and the user's browser may take
  different paths. A static configuration does not prove the effective path.
- No-response and unavailable measurements are unknown. Public endpoints can be
  down, blocked, rate-limited, or return misleading content.
- STUN validates the transaction, packet length, address attributes and optional
  fingerprint. UDP STUN has no server authentication here; a successful response
  is not a cryptographic guarantee against an on-path attacker.
- Browser snapshots are user-provided files, not signed evidence. Five-minute
  freshness checks limit accidental stale comparisons, not deliberate forgery.
- DNS authoritative observation is unimplemented. DNS configuration, Fake-IP,
  or reachable DoH cannot turn that check into a pass.
- IP equality is not proof of ownership, geography, residential status, access
  eligibility, or account safety. Language and timezone are contextual signals.

## Requests and secrets

Desktop network probes require the user's test-button click. Online CLI probes
require `--online`; raw UDP additionally requires `--stun`.
Public probes contact Cloudflare, ipify, ipinfo, Claude/Anthropic and Google STUN.
Those services see the request's source. HTTP requests are unauthenticated GETs
or HEADs; CLI extra targets are supplied by the operator.
The desktop page sends browser observations only to its loopback process, using
a same-origin session token and Origin/Host validation. The fixed action API
validates parameters independently of the UI; no executable, Shell or arbitrary
command line is accepted. Tests and operations share a single concurrency lock.
There is no upload to an external EnvScope server and no analytics.

Explicit proxy credentials go to curl via stdin, not process arguments. No
direct-path fallback is attempted. Unspecified proxy mode follows curl's
environment configuration and OS routing, not necessarily browser settings.
The runtime-config adapter accepts literal loopback HTTP origins only, bypasses
environment proxies and refuses redirects; it exports only selected fields.
Automatic proxy discovery accepts credential-free literal loopback endpoints
only, reads known settings and never scans ports. Manual explicit proxy tests
may use an operator-supplied remote proxy; they do not change OS proxy settings.

Additional checks read only selected configuration and metadata. They do not
execute PAC/WPAD, CLI candidates or MCP commands, and do not export credential
values, other hosts entries, proxy bypass hostnames or raw HTTP headers/cookies.
Loopback TCP checks are bounded to four already-configured endpoints. DNS/route
collection runs in a deadline-bound subprocess; OS route selection is not
per-process traffic or packet evidence. TLS checks never disable verification.
HTTP Date/Age comparisons are hints, not authenticated NTP. Optional absent
configuration is skipped rather than treated as a fault.

Default reports replace IPs with local aliases and remove recognized secrets
and URL query strings. This is not complete anonymization: timezone, language,
platform and software details can remain identifiable. Raw reports and browser
snapshots are private. Never attach them unreviewed to a public issue.

## Accounts and maintenance

Every launch/switch requires a fresh server-side native audit; caller-provided
reports cannot authorize it. Required checks, freshness and all failed findings
are enforced in the action layer, not just by disabled buttons. Browser input
retains its original maximum five-minute measurement window, is re-evaluated,
and is not signed attestation.

Native account copying uses verified staging, per-state OS locks and rollback.
Symlinks/reparse points, traversal, overlaps and pending transactions are refused.
Failures preserve copies; power-loss recovery is manual. A separate legacy
account manager does not honor this lock: do not run both concurrently.
Local snapshot copies do not include every OS credential-store item or guarantee
server-session continuity. Native directory export is **unencrypted**. Optional
retention deliberately copies listed paths across identities; do not list cookies
or credentials unless that sharing is intended.

macOS encrypted DMGs use the original password-stdin path; passwords never enter
argv or returned plans. Original installers/repair scripts retain their own
privilege, backup and rollback behavior. Their bundled hashes verify provenance,
not native-device acceptance. Installers can register background services and
the macOS original updater. Original output is marked unverified by EnvScope.

Local history and preferences are under `~/.envscope`; no raw addresses are
stored there by the normal UI. Comparison uses a private random HMAC key and
does not infer IP ownership or risk. Loss of that key invalidates comparisons.
Redaction is best effort, not a guarantee of anonymization.

## Reporting an issue

Use GitHub's private vulnerability reporting when enabled. Do not publish proxy
credentials, browser profiles, account snapshots, access tokens or real network
addresses in an issue. Include a minimal synthetic reproduction and version.

Supported development line: current `main`. EnvScope has no whole-product updater.
Explicit original-core installation/update is separate and can install the
upstream macOS scheduled updater. Windows/macOS native action acceptance,
administrator cancellation and real-session round trips remain release gates.

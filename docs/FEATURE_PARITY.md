# Feature parity and integration audit

## Active full-scope work: 0.22 development

[The current complete requirement ledger](FULL_PARITY_AUDIT.md) takes precedence
over historical status tables below. Windows CSNAP001 interoperability is now
implemented separately from ENVSNAP1, with original A–D slot constraints,
authentication before decryption, bounded ZIP inspection, exclusive publication
and independent .NET crypto/ZIP exchange. See [its scope](CSNAP_ARCHIVES.md).
Native process protection is now implemented
with a separate user task, ten-second checks, approved scope, PID/path/user
validation, live-worker heartbeat and durable logs. See [its exact scope and
verification](PROCESS_GUARD.md). The native privileged Mac timezone service now has
reviewed install/update/remove, rollback and recovery paths. Native system network
repair is implemented in 0.17. Version 0.18 adds reviewed client lifecycle,
persistent Clash Verge TUN repair and typed Mac Claude-language transactions.
Legacy component migration and real-device acceptance remain incomplete; the
overall parity goal is not achieved. Version 0.21 adds persistent optional probes,
FlClash lifecycle integration and diagnostic ZIP export. Latest discovered upstream
is `a45cede`; the full ledger tracks its remaining Windows changes separately.

Whole-profile account volumes now use normal client exit, APFS copy-on-write
where supported, commit readback and a v2 journal with reviewed recovery UI.
Interrupted recovery is resumable and displaced copies are retained. Synthetic
identity fixtures and a real disposable child-process exit are tested; real
Claude credentials and server device recognition remain unverified.
See [account volume scope](ACCOUNT_VOLUMES.md).

## Current scope: 0.18.0 (2026-10-29)

0.18 stages client repair before a fresh audit and subsequent native guard plans.
It preserves preference comments/fields, exact program identity, original startup
state, typed language arrays and missing/ByHost keys. Confirmed actions, rollback,
durable pending recovery and selected-check UI use the same native coordinators.
Windows named-pipe and Mac CFPreferences/owned GUI acceptance are separate from
real VPN or Claude UI claims. See [client scope](CLIENT_REPAIR.md).

0.17 adds native Windows/macOS IPv6 interface selection and DNS cache flush.
The one-stop and selected-check workflows review exact effects before foreground
OS authorization, preserve protected originals, independently read back changes,
and expose rollback and interrupted recovery. Cache contents cannot be undone;
settings readback never substitutes for DNS, connectivity or egress evidence.
See [network scope and recovery](SYSTEM_NETWORK.md). Additional client-specific
TUN controls and legacy component migration remain guided or incomplete.

0.16 adds a small root-owned native Mac timezone worker, a 60-second LaunchDaemon,
explicit foreground administrator authorization, protected transaction backups,
independent readback, rate limits and pending-operation recovery. Region changes
update the installed guard baseline; undo restores the old files and timezone.
The one-stop maintenance plan includes required system authorization and compensates
a failed user-task registration. Root launchd tests use compile-time fixture paths
on both Mac architectures; they never change the runner's real timezone.
Actual user authorization dialogs remain a real-device acceptance item.
See [timezone service scope](TIMEZONE_SERVICE.md).

0.15 adds native macOS DMG compatibility with the original root marker and A–D
slots. Encrypted-image checks, read-only mounts, bounded profile validation,
readback, exclusive publication and explicit interrupted-workspace cleanup run
without vendor scripts. New images add a file manifest inside the existing marker;
old images retain their narrower checksum/copy verification scope. Unit and UI
fixtures are separate from actual hdiutil and frozen Mac acceptance in release CI.
See [DMG archive scope](DMG_ARCHIVES.md).

0.14 adds native Clash Verge routing: reviewed 16-rule plans, preserved user
scripts, bounded comment-preserving YAML edits, durable backups, actual runtime
readback, rollback and restart recovery. Windows/macOS UI fixtures and an actual
temporary Windows Mihomo core have passed; macOS Unix-socket results are recorded
by the release CI. Other clients remain guided. [Routing scope](ROUTING.md).

0.13 added account-volume recovery and a separate 10-second process guard.
Three native architectures passed frozen account roundtrips, interruption
recovery, user-task registration / multiple automatic executions / removal,
tray operations and full archive updates. Real Claude login, GUI regeneration,
power loss and proxy failure on user devices remain separate acceptance work.

IP lookup now filters city presets by the observed exit country and suggests
timezone/locale/language only with explicit evidence and user confirmation.
The native Watchdog adds approved timezone/locale recovery, reopening a selected
offline proxy client, node restoration with a TLS recheck, cooldown and durable
daily event logs. Background elevation is not performed; macOS privileged
timezone recovery still requires the legacy service or manual action.
Account exchanges preserve complete per-account directories; retention is now
restricted to `skills/` to prevent cross-account identity/session mixing.
[Current details and limits](WATCHDOG_AND_IDENTITIES.md).

The 55-row catalogue now supports full selection, filtering, individual and
batch checks with explicit dependencies, and reviewed batch repairs. It includes
derived acceptance rows, not 55 independent network probes. Native Windows/macOS
region actions use explicit city presets, readback and a private recovery record.
An existing loopback Mihomo-compatible Selector can be changed; no nodes are
created, country labels are not geolocation evidence, and official region
qualification remains a separate gate. [Workflow and boundaries](SELECTIVE_CHECKS.md).

The current product exposes a 23-task capability map and eight-dimension
evidence view. Both platforms now implement temporary-browser sessions,
authenticated `.envsnap` archives, passive CLI conflict/provenance inspection,
and broader device/browser metadata. Installed guard modes are compared with
the selected client. CN/RU are rejected by a separate official-region gate.

Upstream main was reviewed at `223a5cc44edf36dfa568903ab02e73f0f015ec9e`.
The bundled immutable pin remains `870c4ca`. Remaining system network repairs,
Mac privileged timezone watchdog and DMG compatibility depend on explicitly installed legacy
components. [Current implementation and tests](ENVIRONMENT_COVERAGE.md).

The dated sections below record prior audits. Former native browser, archive
and tray gaps are superseded where stated above. Firewall enforcement,
authoritative DNS egress and server-side account qualification remain unverified.

## 0.7.1 usability and upstream refresh (2026-10-28)

The complete 14 + 18 index is now a first-class page, available before a run,
with search, status filters, explanations and explicit missing evidence. Native
CLI and basic device information work on Windows and macOS without installing
the legacy backend. Account guidance distinguishes a local slot from a real
login and offers current-profile adoption, first login and archived-profile
switching. Read results appear beside their controls. Visible-page heartbeats
and an offline banner address expired loopback tabs.

The current upstream main was verified as `f20a38aaa4cd70947eb3ea929cd47c60e62a3463`.
It is five commits ahead of our immutable pin. The changed executable source is
`windows/claude-switch.ps1`: `Get-ClashApi` now falls back from `clash-verge.yaml`
to `config.yaml`. This change is **not** in the bundled maintenance core.
The other changed files are an ignore file, its static regression, and two
Windows native EXE planning/specification documents. Those documents do not
establish that a WPF client or installer has been delivered. The pinned audit
below remains explicitly tied to `870c4ca`; it is not a claim of tracking main.
[Verified upstream diff](https://github.com/YOURSJEYO/claude-switcher/compare/870c4ca0754234965878ef58144d7a755d965037...f20a38aaa4cd70947eb3ea929cd47c60e62a3463).

| User task | claude-switcher pinned baseline | EnvScope 0.7.1 |
|---|---|---|
| Inspect environment | 14 categories | 14 baseline + 18 extended categories, additional independent measurements, readable guidance |
| Save desktop identities | Mac A–D; Windows A/B UI | Named dynamic slots, verified staged copies, rollback and fresh preflight |
| Repair configuration | System/proxy/routing oriented | Adds Code field previews, backups, undo and independent recheck; system repairs still use legacy core |
| Keep settings | Process guard; Mac timezone watchdog | Adds scheduled checks and approved Code field restoration; these are not process guards |
| Mac auxiliary tools | Encrypted DMG and temporary browser | Retained through separately installed original backend; no native Windows equivalent |

More diagnostic rows do not imply complete replacement of the original product.
The native firewall kill switch, signed automatic product update, cross-platform
encrypted snapshots and Windows isolated browser remain gaps.

v0.7 adds a native desktop handoff in the main workflow: reviewed launch or
graceful restart, a fresh native preflight before each launch, installation and
desktop JSON checks, account recovery and locking, and a separate Claude web
endpoint condition. It does not exchange profiles or certify authentication.
Frozen Windows, Apple Silicon and Intel packages now have a real OS scheduler
lifecycle release gate: registration, two automatic worker runs, and removal.
See [product acceptance scope](PRODUCT_ACCEPTANCE.md).

v0.4 exposes all 14 upstream identities as an evidence/remedy/upkeep checklist,
adds reviewed per-item entry points, cross-restart verified config undo, and
native user-scoped scheduled checks on Windows/macOS. Optional drift recovery
only restores five approved Code env keys; it does not replace the upstream
process guard, timezone watchdog, account manager or system repair. See
[checklist and maintenance boundaries](CLAUDE_CHECKS.md). Real OS task lifecycle
acceptance was pending in v0.4; v0.7 adds the isolated lifecycle gate described
above. Login and sleep transitions remain outside that gate. Windows definitions
are also checked against the official XSD.

v0.3 adds evidence-based problem interpretation and an integrated solution flow:
explicit observations, causes, ordered steps, fixed settings/file entries,
reviewed configuration edits, private backups, session-scoped undo and fresh
verification. Ambiguous configuration syntax and remote account/service issues
are not guessed or reported as automatically repaired. See [diagnosis rules and
acceptance](DIAGNOSIS.md).

Audited source: `YOURSJEYO/claude-switcher`, commit
`870c4ca0754234965878ef58144d7a755d965037` (2026-10-27 audit).
The pinned source is retained in `envscope/vendor/claude_switcher/`; its MIT
notice and source boundaries are recorded in `THIRD_PARTY_NOTICES.md`.
The audit read code and documentation without running an installer, updater,
repair, account switch, background service, or upstream `checkdetail`.

The upstream product is a launcher, account manager, maintenance tool and
diagnostic suite. A browser leak report alone is not feature parity. Windows
upstream is Beta and has fewer commands and weaker safeguards than macOS.

Status terms below describe implementation boundaries, not real-device approval:

- **Native**: EnvScope code implements the stated scope. The account backend is
  fixture-tested; this does not certify real Claude sessions or macOS devices.
- **Legacy adapter**: `envscope/legacy.py` can expose a fixed action from the
  separately installed original backend after the explicit action flow. Bundled
  source is not itself an installed service. Its output remains upstream-reported
  evidence and does not become an independently verified privacy pass.
- **Gap**: the native equivalent is absent; retaining source does not fill it.
- **Not upstream**: the pinned upstream does not implement it on that platform.

## Exact command surface

| Command / capability | macOS upstream | Windows upstream | EnvScope integration boundary |
|---|---|---|---|
| `check` | Summary `OK:`/`FAIL:` with last-IP/history writes; `core/claude-switch.sh:651` | **Not dispatched**, despite its header comment | macOS legacy adapter; native audit is a different evidence model |
| `checkdetail` | 14 rows plus recorded output; `core:770`, dispatcher `:1706` | 14 rows and `last-check.txt`; `windows/claude-switch.ps1:561,:976` | Legacy adapter; saved text import remains unverified; native diagnostics remain separate |
| `status` | Current slot, A-D flags, archived slots, size/date; `core:1438` | Current slot and A/B flags only; `windows/core:746` | Native `AccountManager.list_accounts()` adds dynamic slots, labels, bytes, timestamps and pending state |
| `switch <slot>` / launch current slot | A-D, first-run adoption into A; `core:1614` | GUI A/B; core accepts an unvalidated string; `windows/core:771` | Native transactional account API; deliberately bypasses neither preflight nor process-exit confirmation |
| `fix` | Start proxy; restore Clash TUN; timezone/IPv6/DNS/guard; locale/Claude language; routing/STUN retest; `core:874` | Start Clash; timezone/IPv6/DNS/guard; routing migration/restart/rollback; `windows/core:619` | Legacy adapter; ordinary EnvScope detection remains read-only |
| `set-region` | Re-detect country/timezone/locale, update core and watchdog; `core:1047` | Not upstream; reinstall/manual edit required | macOS legacy adapter; native cross-platform region editor is a gap |
| `set-client <mode>` | `clash-verge`, `shadowrocket`, `sing-box`, `clashx`, `surge`, `auto`; `core:1024` | No command; installer sets mode | macOS legacy adapter; discovery is distinct from modification |
| `fingerprint` | Fonts, GPU/display, virtualization; informational and nonblocking; `core:1202` | Not upstream | Native basic OS/architecture and graphics information on both platforms; Windows model/driver/font count. Original Mac detail retained under `legacy-fingerprint`; no risk inference |
| `cli-info` | PATH/real path/version, native/brew/npm/bun classification, desktop CLI, install conflicts, config size; `core:1240` | Not upstream | Native PATH/config-directory inventory on both platforms, without running discovered programs. Original Mac detail retained under `legacy-cli-info`; native full version/conflict classification remains a gap |
| `open-safe <http(s) URL>` | Chrome/Chromium/Edge/Brave temporary profile, disabled sync/extensions/non-proxied UDP, language setting, cleanup; `core:1291` | Not upstream | macOS legacy adapter; native Windows isolated-browser launch is a gap |
| `snapshot-export <A-D> <file> [--password-stdin]` | Inactive archived slot to verified AES-256 DMG; `core:1330` | Not upstream | macOS encrypted legacy adapter. Native `copy_snapshot_to` is only a verified **unencrypted directory hook** |
| `snapshot-import <file> <A-D> [--password-stdin]` | Readonly DMG mount, metadata/slot validation, refuse occupied slot, staged import; `core:1378` | Not upstream | macOS encrypted legacy adapter. Native `import_snapshot_from` copies a validated directory into an empty inactive slot |
| `update [--check\|--auto]`, `update-check` | Download main, verify source hashes, preserve 5 settings, back up core, self-check/rollback; auto every 12h; `core:1098` | Different command names, see next row | macOS legacy adapter; updates original installation only, not EnvScope |
| `check-update`, `update-now` | Not upstream under these names | Latest GitHub Release; zip SHA256, preserve 4 settings, backup/rollback, restart guard; `windows/core:804,:853,:857` | Windows legacy adapter; updates original installation only |
| `diagnose-proxy --proxy URL\|--config FILE` / explicit env var | Independent HTTP/HTTPS/SOCKS5/SOCKS5h TLS transport test for Claude web/API; dispatched before account state; `core:8` | No native PowerShell command | macOS legacy adapter; EnvScope explicit-proxy HTTP targets provide a broader native transport foundation |
| Internal routing entries | `write-merge-rules`; `clash-rules` internal protocol; `core:143,:871` | Rule helpers are internal functions | Keep internal, not arbitrary executable-command inputs |

In source-location shorthand above, `core` means `core/claude-switch.sh` and
`windows/core` means `windows/claude-switch.ps1` inside the pinned upstream.
The Windows dispatcher at `:975` contains exactly `checkdetail`, `status`,
`fix`, `switch`, `check-update`, `update-now`.

## The 14 upstream checks

These are the exact row identities. Retaining their categories does not require
retaining unsupported pass rules or account-risk claims.

| # | Row | macOS measurement | Windows measurement / gap | Integration rule |
|---|---|---|---|---|
| 1 | 代理内核 | Selected process or Shadowrocket VPN state | Process/service; `other` skips process check | Report recognized client and measurement scope; process presence is not route proof |
| 2 | TUN网卡 | Any IPv4 `198.18.*` address | Same, then Up adapter-description heuristic | Preserve as inventory clue; do not claim full traffic takeover |
| 3 | 出口IP | Cloudflare trace country equals configured target | Same | Keep target-country comparison separate from IP ownership and account safety |
| 4 | IP一致 | Last IP plus unique IP count in rolling 48h; >=3 warns | Last IP only | History changes are observations; not a measured ban-risk predictor |
| 5 | 时区 | `/etc/localtime` equals IANA target | `Get-TimeZone` equals Windows ID | Compare normalized system identifiers; handle mapping failures explicitly |
| 6 | 地区 | AppleLocale equals configured locale | Hardcoded `en-US`, regardless of country | Native Windows country-adaptive locale is an upstream gap |
| 7 | IPv6 | Wi-Fi IPv6 configuration says off | No enabled `ms_tcpip6` adapter binding | Configuration and actual IPv6 reachability are separate findings |
| 8 | DNS | `claude.ai` resolves to Fake-IP `198.18.*` | Same; false failures possible for non-Fake-IP clients | Native authoritative DNS remains unknown until actually measured |
| 9 | WebRTC | Native UDP STUN, runtime-rule check, proxy/reject policy | Native IPv4 .NET STUN; no response incorrectly yields `ok` | Keep native UDP and browser ICE separate; timeout is unknown |
| 10 | 保镖 | LaunchDaemon can be queried | Scheduled task exists | Registration is not a verified running guard or packet-level kill switch |
| 11 | 规则置顶 | Runtime `/configs`, `/rules`, `/proxies`; exact order, target, enabled state and selected-node UDP support; global bypass | First16 domain/port counts; no destination, disabled, UDP or group-selection validation; global/direct marked ok; non-Clash warns | Use macOS validation semantics as the stronger routing baseline; configuration-only fallback cannot verify enforcement |
| 12 | 客户端语言 | Claude defaults or preferred system English | Unconditionally emits `ok:跟随系统` | Windows requires real measurement or unknown, not a fabricated pass |
| 13 | ASN属性 | ipinfo organization text against country-specific ISP name list | Short US-name list | Display ASN/organization as metadata; names cannot establish residential service or account risk |
| 14 | 生态可达性 | Any non-`000` response from Claude web/API | Same | Distinguish TLS transport, 401 authentication, 403 access, 429 throttling and 5xx; response is not account availability |

Source: macOS `core:770-867`; Windows `windows/core:561-617`.
Both upstream `checkdetail` paths write state; neither is a read-only import API.
macOS UI allows `warn` rows and demands 14 distinct rows plus valid account state.
Windows counts matches rather than unique rows. A claimed 14/14 is not proof of
privacy, supported geography, an authenticated account, or packet-level isolation.

## Background protection, routes and everyday UI

| Capability | macOS upstream | Windows upstream | Integration status / priority |
|---|---|---|---|
| Guarded launch | Swift `switchTo` rechecks before every launch; `app/main.swift:350` | GUI `Switch-To` directly invokes core even after failed checks; `windows/SwitcherUI.ps1:169` | Native account API requires affirmative callback preflight. The shared action layer must supply actual evidence and block stale/unknown required items |
| Exit before exchange | Graceful Claude quit, wait <=15s; `core:1456` | Forced process stop, wait <=15s; `windows/core:753` | Native callback must affirm exit before any profile copy/commit |
| Snapshot safety | `.new`/`.previous` archive protection, staged load, APFS clone fallback to ditto; `core:1466,:1521` | `robocopy /MIR` without checked exit codes; deletes live DATA before restore | Native verified-copy rollback replaces this Windows path; preserve legacy folder structure |
| Process guard | Root-owned daemon script, every 10 s, process + Fake-IP TUN; `daemons/claude-bodyguard.sh` and plist | Hidden PowerShell loop, login scheduled task, every 10 s; explicit client modes + TUN; auto/other TUN only | Pinned templates and installer retained via legacy adapter; no claim of native firewall enforcement |
| Timezone watchdog | Root daemon resets drift every 3600 s; `daemons/tz-watchdog.sh` and plist | Not upstream | Native Mac root worker every 60 s, reviewed lifecycle/undo and baseline integration; Windows user-task recovery is permission scoped. Legacy concurrent daemon is detected and requires explicit manual disable |
| Automatic update | User LaunchAgent every 43200 s runs real update; root daemons only compared and reinstall suggested | UI startup check; 24h cache/dismissal; manual check; one-click apply | Legacy paths retained. Native signed whole-product updating is a separate gap |
| Routing domains | 13 suffixes including Claude, Anthropic, Turnstile, telemetry, payments and support | Same 13 | Retain list and runtime validation; do not infer application success from routing |
| STUN routing | UDP-only AND rules for 3478/5349/19302; `WEBRTC_POLICY=proxy` or `reject`, persisted | Generic DST-PORT rules for the same ports; no reject-policy switch | Native Windows stronger UDP policy is a gap; do not silently equate the two implementations |
| Route migration | Preserve/combine existing Script main; backup; migrate only upstream Merge marker block | Insert/replace Script managed block; broader legacy Merge cleanup; backup/restart/runtime test/rollback | Retained explicit repair actions; review previews and backups before application |
| Cross-identity retention | Optional `keep-in-workspace.txt`; relative paths, no traversal or symlink components, staged merge, failure refusal; `core:1538-1612` | Not upstream | Native manager reads the same optional list on both platforms and merges only into the staged target; malformed paths refuse the operation |
| Mac resident UI | Menu-bar shield; current account/recent check; open, recheck, update, quit; close hides; switch success hides after 2.2 s | No tray/menu equivalent | Existing source retained. Native cross-platform tray residency is a gap |
| Account cards | A-D, initialized state, size/date and first-login hint | A/B only | Native API supports A-D plus validated dynamic IDs and separate labels; call-site/UI wiring is distinct |
| Extra panels | Fingerprint, security notice, update result/copy command, AI handoff copy, missing-core install help | Check/fix/refresh + async update banner/later/manual check | Legacy GUI source retained; native interface should expose practical actions without importing unsupported security promises |
| Installation | Proxy/group discovery, country/timezone/locale, service installation, Swift app/icon/signing, routing and post-check | Admin script, proxy/group discovery, limited timezone mapping, guard task, shortcut | Pinned installers available only as explicit actions; downloading EnvScope does not imply services were installed |
| Uninstallation | Remove app/core/services, preserve account snapshots; OS settings and custom rules need separate review | Manual removal in README; no uninstaller script | No claim of complete settings restoration; inventory what was changed before future reversible native install/remove work |
| Browser diagnostics | Static zero-install page: IP/region, browser ICE, IPv6, approximate DNS, Canvas/WebGL/device info | Browser page works independently of OS | Native HTTP/ICE and merged reports; on-demand local Canvas SHA256, WebGL and screen/thread information; DNS remains unknown without authoritative evidence |

Routing suffixes: `claude.ai`, `claude.com`, `anthropic.com`,
`claudeusercontent.com`, `challenges.cloudflare.com`, `datadoghq.com`,
`segment.io`, `stripe.com`, `stripe.network`, `stripecdn.com`, `intercom.io`,
`intercomcdn.com`, `intercomassets.com`.

The upstream guard is process termination on a 10-second polling interval. Its
own `SECURITY.md` acknowledges the packet window and lack of a firewall boundary.
The native probe is not browser WebRTC. The upstream browser page's DoH
reachability, silent IPv6 and mDNS heuristics must not be copied as proof of no
leak. EnvScope retains explicit unknown/incomplete results for those cases.

## Native account API and verification

`envscope/accounts.py` supplies:

```python
AccountManager(state_dir, data_dir, current_filename=None,
               stop_app=None, launch_app=None)
manager.list_accounts()
manager.rename_label(slot, label)
manager.switch(slot, preflight=callable)
manager.copy_snapshot_to(slot, destination)       # raw directory, unencrypted
manager.import_snapshot_from(source, slot)       # empty inactive slot only
```

`current_filename` is `current.txt` on Windows and `current` elsewhere. Reading
accepts the alternate legacy marker; disagreement refuses mutation. Switching
requires preflight to return exactly `True`; process exit must also be exactly
`True`. No process commands are built or executed inside this module. A caller
must inject platform operations, and no callback is invoked by construction,
listing or label changes. Same-current launch still needs preflight but does
not stop the application unnecessarily.

Slots accept 1-32 ASCII letters/digits/underscore/hyphen, reject Windows reserved
device names and case collisions, and retain A-D compatibility. Labels are
separate metadata, never directory names. Snapshot/live storage may not overlap.
Symlinks, Windows reparse points and special files are refused. Every staged copy
is checked against a SHA256 file-tree manifest before commitment; no code path
recursively deletes the live DATA path. A per-state OS lock serializes native
account writers.

As of 0.12, optional `keep-in-workspace.txt` defaults off and is intentionally
restricted to `skills/` paths. Identity, session, Cookie and settings paths refuse
the exchange before stopping the application. This narrows upstream retention
to preserve account isolation. Staging, traversal/link refusal and preservation
of legacy `keep-stage` leftovers remain in place.

On an exception during copy/commit/marker update, rollback restores the original
live tree, previous snapshot and markers. Cleanup/rollback failure leaves
recovery copies and blocks launch. A persistent journal and incomplete
`.new`/`.previous` paths block subsequent writes rather than guessing which copy
to discard. This is in-process rollback and crash-state preservation; automatic
reconstruction after a power loss is not implemented. The original maintenance
tool does not participate in this lock, so concurrent use of both tools must be
avoided.

The raw-directory hooks are building blocks for an encryption layer. They do not
encrypt at rest and do not promise cross-OS session migration. Export refuses an
active slot and managed-path destinations; import refuses an occupied/current
slot. Server-side revocation, OS credential storage and files outside the Claude
profile tree are outside the copied snapshot's scope.

`tests/test_accounts.py` uses temporary directories and injected callbacks only.
It exercises round trips, first adoption, dynamic labels, legacy markers,
invalid slots, interrupted states, partial/corrupted copies, failed rename,
marker failure, cleanup failure, failed rollback, concurrency and import/export.
The Windows run passed 34 account tests; one real symlink test skipped because this host
lacks symlink privilege. A simulated reparse test passed. These results are not
macOS or real-account acceptance.

## Integration order and release evidence

1. Keep explicit read-only measurement separate from explicit account/repair/
   update/install actions. The shared launch action must enforce preflight for
   both platforms; a disabled button or inherited status text is insufficient.
2. Route account switching through the native verified transaction API. Preserve
   the upstream snapshots and recovery artifacts. Do not route Windows switching
   through the destructive legacy implementation.
3. Expose the exact platform capability catalog, installed-backend availability,
   concrete action effects, and unsupported gaps. Retain original functions
   through fixed adapters instead of dropping them from the product surface.
4. Add practical native history/compare, proxy discovery and differentiated
   connectivity diagnostics. Do not let an old report or imported `ok` authorize
   launching the application.
5. Port missing Windows system region/client controls, isolated links,
   complete CLI version/conflict classification and encrypted snapshots as
   independently tested modules. Native encrypted export is not complete merely
   because a plaintext copy hook exists.

6. Verify installers, service lifecycle, UAC/administrator cancellation, network
   loss, sleep/resume, rollback and real session round trips on selected Windows
   and macOS test devices. Ordinary development tests must remain isolated.
   Packaged source or CI configuration alone does not prove those behaviors.

The integrated version supplies native fourteen-category observations,
live rule-order/destination/disabled/node/UDP validation, a fixed action API,
server-side launch remeasurement, five minimal desktop pages, history/HMAC
comparisons, proxy discovery/diagnosis, support bundles and preference recovery.
Long account copies renew preflight before application launch. The CLI and web
service both expose the native baseline. Windows hardware/CLI inventory is
informational and has the narrower scope shown above. These additions do not
convert untested installed-system behavior into native-device acceptance.

Version 0.2 also supplies eighteen additional measurements: target system DNS
and selected routes, hosts overrides, system/environment proxy differences and
bypasses, configured loopback listeners, runtime TUN and controller binding,
TLS verification, phase timings and HTTPS-date clock comparison, desktop/profile/
JSON discovery, CLI entry/environment conflicts, disk capacity and account
structural integrity. Findings include remediation suggestions; filters affect
display only. Guard checks require enabled and running state, not registration
alone. Selected system routes do not close the per-process traffic evidence gap.

Platform boundaries still requiring evidence include macOS Intel/Apple Silicon,
actual CLI/browser locations, Windows Store versus classic Claude packaging,
the Windows updater/task permissions and macOS helper ownership. Upstream source
can build Intel macOS, while its pinned release workflow names arm64 app-only
assets. Neither source retention nor bundling converts that into a tested
universal product.

# Development rules

- Native diagnostics remain read-only. Development and tests must not change
  real networking, timezone, locale, firewall, installed applications, accounts,
  or proxy settings. Explicit product maintenance actions are separate and
  must disclose their concrete effects and require a boolean confirmation.
- Route all account switching through AccountManager and fresh server-side
  preflight. Never call the destructive legacy Windows switch path. Preserve
  recovery artifacts; do not discard a pending transaction automatically.
- Treat vendor files as immutable, byte-exact data. Do not run vendor AGENTS,
  tests, installers or scripts during development. Preserve all pinned hashes,
  executable metadata and original licenses in wheels and desktop packages.
- Unknown, timeout, unsupported, stale, skipped, and malformed results must never
  become a privacy pass. Every pass must state its measurement scope.
- Native UDP STUN is not browser WebRTC. Relay candidates are not the client's
  public address. Compare IPv4 and IPv6 separately and use explicit allowlists
  before declaring an observed address a policy violation.
- Do not import upstream reported `ok` as verified evidence.
- All network tests in the regression suite use fixtures or loopback servers.
- Do not add Scrapling to runtime dependencies; it is a research collection tool.
- Keep third-party origins and license boundaries in THIRD_PARTY_NOTICES.md.
- Before release: Python tests, JavaScript tests and syntax, package build,
  desktop browser smoke test, visual inspection, and secret/report exclusion checks.
- Product targets are Windows and macOS. Defer mobile adaptation. Keep the UI
  monochrome and minimal, with one test button and automatic result merging.
- Never commit real diagnostic reports, proxy credentials, browser profiles, or
  source research captures. GitHub publication requires a reviewed repository.

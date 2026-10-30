# Third-party origins

## Region and timezone data

`envscope/region_data.py` contains derived data from Unicode CLDR 48, revision
`acd6d88ae493633240e19a87a721076a8a75c310`, under Unicode-3.0.
The complete license is in `licenses/Unicode-3.0.txt`. The generator
`scripts/generate_region_data.py` records each input SHA-256 and uses the official
CLDR Windows timezone mappings, Chinese place names, timezone aliases and likely
language defaults. These are editable configuration suggestions, independent of
Claude's supported-region policy and never evidence of a user's physical location.
Source: https://github.com/unicode-org/cldr/tree/acd6d88ae493633240e19a87a721076a8a75c310

## WireGuard interoperability

The read-only Windows service adapter is EnvScope code using documented Windows
SCM / process APIs and the WireGuard for Windows service naming / argument
contract. It does not bundle or execute WireGuard source, binaries, drivers or
configuration files. WireGuard is maintained by its own project; see its
[enterprise documentation](https://git.zx2c4.com/wireguard-windows/about/docs/enterprise.md)
and [EnvScope's scope and validation](docs/WIREGUARD.md).

## Original CSNAP001 interoperability

The native `.csnap` adapter follows the Windows CSNAP001 byte-format and root
marker contract in claude-switcher at
`a45cede34042922f881ef9672148cc7c8ddccff1` (MIT, credited below).
No source scripts are run. The implementation uses Python's PBKDF2/HMAC and
cryptography's AES-CBC/PKCS7. Independent, self-authored .NET crypto and ZIP
fixture code checks interoperability; it is test tooling and is not bundled
into the application. See [format and verification scope](docs/CSNAP_ARCHIVES.md).

## Original DMG interoperability

The native macOS DMG adapter preserves the encrypted root layout and A–D marker
contract of claude-switcher at `870c4ca0754234965878ef58144d7a755d965037`, credited
below. It calls the user's Apple-provided `/usr/bin/hdiutil`, which is not bundled,
and never executes the vendor export/import scripts. The compatibility tests
generate disposable fixture images. See [archive scope](docs/DMG_ARCHIVES.md).

## ruamel.yaml and routing interoperability

Comment-preserving YAML edits use [ruamel.yaml](https://yaml.dev/doc/ruamel.yaml/),
MIT licensed, runtime range `>=0.19.1,<0.20`. Only its pure Python round-trip
parser is used; unsafe Python object constructors are never enabled. Its license
is included in desktop packages. Duplicate keys, cycles, custom tags and excessive
input depth / size are rejected before any write.

Native routing interoperates with the documented Clash Verge global script format
and Mihomo local control API. The generated wrapper follows the reviewed
claude-switcher managed-script composition, retaining upstream attribution below.
The release validation downloads unmodified official Mihomo v1.19.33 binaries
(GPL-3.0) into ignored test artifacts and checks pinned SHA-256 digests. These
test binaries are not shipped with EnvScope; their source is available at
https://github.com/MetaCubeX/mihomo/tree/v1.19.33 .

## cryptography

Encrypted `.envsnap` archives use [cryptography](https://github.com/pyca/cryptography),
licensed under Apache-2.0 OR BSD-3-Clause. Distribution licenses, including its
bundled component notices, are retained in native package licenses. EnvScope
uses Scrypt and AES-256-GCM, not a custom cipher. Runtime range:
`cryptography>=46,<51`; the release build records the resolved version.
macOS bundles require static OpenSSL linkage to avoid collisions with Python's
runtime. Intel CI compiles the current cryptography source with `OPENSSL_STATIC=1`;
the shared OpenSSL license is retained in `licenses/OPENSSL-LICENSE.txt`.

EnvScope is MIT licensed. It contains no Scrapling, proxy core, browser automation
framework, VPN application, account database, or captured research pages at runtime.
Desktop distributions bundle Python through PyInstaller; applicable runtime and
bundled library notices accompany the generated artifacts.

The independent desktop shell uses pywebview (BSD-3-Clause,
https://github.com/r0x0r/pywebview), pystray (LGPL-3.0,
https://github.com/moses-palmer/pystray), and Pillow (HPND,
https://github.com/python-pillow/Pillow). They are unmodified, optional desktop
dependencies. Their licenses are copied from the installed distributions into
desktop packages. pystray's corresponding source is the upstream 0.19.5 release;
users may replace it and rebuild with `python -m scripts.build_desktop`.
The shell uses the OS WebView (WebView2 on Windows, WKWebView on macOS); it does
not bundle a Chromium browser. Python.NET/clr_loader and PyObjC supply platform
bindings, with their installed license files retained in the package.

The `licenses/` directory supplies the Python/PSF, OpenSSL/Apache-2.0 and
libffi/MIT notices for bundled runtime components. The builder also retains the
installed Python license and PyInstaller's complete COPYING notice, including
its bootloader distribution exception. Python and these components are not
modified. Runtime libraries retain their respective copyrights and licenses.

## claude-switcher

Origin: https://github.com/YOURSJEYO/claude-switcher

Reviewed revision: `870c4ca0754234965878ef58144d7a755d965037`.
License: MIT. Copyright (c) 2026 Claude Switcher Contributors.

The complete 57-file source tree is retained byte-for-byte in
`envscope/vendor/claude_switcher`, with its original MIT LICENSE, SHA256SUMS and
an additional full-file manifest. The manifest digest is anchored in the adapter.
Vendored .py files are data, not imported runtime modules. Linux source is retained
for source completeness; EnvScope does not support Linux as a desktop product.

The native STUN probe design and diagnostic categories are the development base.
`envscope/stun.py` is a rewritten derivative with response identity, length,
attribute, IPv6 and fingerprint validation. Attribution and the complete MIT
permission notice are retained in LICENSE. Existing saved checkdetail reports
can be imported without executing upstream scripts. Native account transactions
replace the original switch path. Explicit fixed adapters expose separately
installed original maintenance and the pinned interactive installers. Those
actions can modify installed-system settings, accounts and background services;
they never run merely because EnvScope starts or performs its native audit.

## Research references

- WebRTC samples, revision `6e2c5a117aa860d66d874f7c0df0ef9a3e2cd74e`, BSD-3-Clause:
  https://github.com/webrtc/samples. Standard API behaviour was studied; the
  sample application and source files are not copied or bundled.
- ExpressVPN Leak Testing Tools, revision `9e4cee899ac04f7820ac351fa55efdc0c01370ba`,
  MIT: https://github.com/expressvpn/expressvpn_leak_testing. Scenario organization
  informs our regression approach; no upstream test runner or dependencies copied.
- Mullvad VPN, revision `0508389502500fdd8e375d1e53756d4053ca23de`, GPL-3.0:
  https://github.com/mullvad/mullvadvpn-app. VM-based end-to-end testing is a
  reference only; no GPL source is incorporated.
- Mihomo API documentation: https://wiki.metacubex.one/api/. The optional adapter
  reads a documented loopback HTTP interface. No proxy core or implementation is
  linked, copied or bundled.
- Clash Verge Rev, reviewed revision `3953e125b223defcec28a3c822c292c743fc1b1e`,
  GPL-3.0: https://github.com/clash-verge-rev/clash-verge-rev. The tool chooser
  links to this separately installed Windows/macOS client and explains its
  system-proxy/TUN role. No implementation, artwork or GPL source is bundled.
- RFC 8489: https://www.rfc-editor.org/info/rfc8489/. Protocol reference.
- Microsoft Find-NetRoute documentation, Apple route command manual, curl manual
  and Claude Code settings documentation are public-interface references for the
  additional checks. No implementation code or document body is bundled from
  those sources; their links and review dates are recorded in docs/sources.lock.json.

Source collection used an external Scrapling 0.4.15 installation. Scrapling is
not a product dependency. Python, Playwright and PyInstaller used for development
or packaging retain their own licenses; installing build tools does not change
the EnvScope source license.

The 0.3 troubleshooting rules reference official Claude Code network/settings
and installation documentation, Claude API error semantics, curl error codes,
and Microsoft Settings URI documentation. These are factual interface and
troubleshooting references; no implementation code is copied. Research captures
stay outside the repository, with provenance in docs/sources.lock.json.

## psutil

Native process and network-interface inspection and identity-checked process
termination use [psutil](https://github.com/giampaolo/psutil), BSD-3-Clause.
It is a runtime dependency; the desktop build includes its distribution license.
Source use follows the [official API reference](https://psutil.readthedocs.io/).
No psutil process operation runs merely from importing EnvScope.

## Native client and language interfaces

Version 0.18 independently implements public OS process / preference APIs and
the documented local Mihomo control protocol. Clash Verge Rev 2.5.8, revision
`4337bd85758d54d7b9044b2da3c9ac1176eae1f3`, was reviewed to understand its
`enable_tun_mode` preference and IPC configuration. No GPL implementation,
binary or artwork is distributed. Apple AppKit/Core Foundation and Microsoft
named-pipe documentation are interface references, not bundled source. See
[exact scope and sources](docs/CLIENT_REPAIR.md).

## FlClash interface review

Version 0.21 independently recognizes FlClash applications and the FlClashCore
process name. The upstream project at
https://github.com/chen08209/FlClash, GPL-3.0, revision
`7fd417fb9a9a277c6a9339a8ac87f907df7c25f7`, was read to verify executable names,
app paths and its distinct preference storage. No implementation, binary or
artwork is bundled or copied. Its TUN preference is not rewritten using Clash
Verge conventions. See [integration scope](docs/CHECK_PREFERENCES.md).

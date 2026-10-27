# Third-party origins

EnvScope is MIT licensed. It contains no Scrapling, proxy core, browser automation
framework, VPN application, account database, or captured research pages at runtime.
Desktop distributions bundle Python through PyInstaller; applicable runtime and
bundled library notices accompany the generated artifacts.

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
- RFC 8489: https://www.rfc-editor.org/info/rfc8489/. Protocol reference.

Source collection used an external Scrapling 0.4.15 installation. Scrapling is
not a product dependency. Python, Playwright and PyInstaller used for development
or packaging retain their own licenses; installing build tools does not change
the EnvScope source license.

# Permission completion and desktop refresh

## Intent and accepted scope

Implement the permission/usability audit requested by the user, verify every optimization, then upgrade the complete desktop UI, application/tray/navigation icons and interaction responsiveness. Preserve Windows/macOS support, a monochrome minimal design and the primary flow: target → one check → problems/repair → persistent guard. Mobile remains out of scope.

The source audit is `artifacts/permission-review-2026-10-30/AUDIT.md`; its six priorities are requirements, not completion evidence. Baseline: `ffbdc3a` / 0.24.1.

## Architecture and approaches

Use the existing Python, native helper and webview architecture. Keep the main process and account state in the original user's session. Use OS-owned consent for specific privileged operations and protected, narrowly scoped native helpers for persistent system work. Reuse backup, report freshness, transaction and independent readback gates.

A permanently elevated application would unnecessarily elevate the browser interface and account operations. Guidance-only permission links cannot satisfy the requested automatic continuation/guard behavior. The chosen implementation extends the existing split-process architecture; this is an implementation decision under the user's requested scope.

## Required outcomes

1. Classify collection failure as permission_denied, policy_denied, timeout, tool_missing, invalid_response or unavailable. Preserve the failed operation in evidence; partial inventory never reports a completed pass. Propagate failures to dependent checks. Do not store raw command stderr or secrets.
2. Describe each requested capability, its affected checks, read/write/background scope and OS action. Provide only actions relevant to observed denial and the selected target. Merely opening settings is never permission_granted. Returning from a permission step triggers bounded capability revalidation and a new report/repair plan, while preserving the user's selected checks and repair receipt.
3. Distinguish cancelled consent, refused policy, an operation failure, pending recovery, restart required and verified success. Unknown execution must reconcile transaction records before retrying a mutation.
4. Check guard capabilities before activation. Windows gains a protected, restricted timezone worker/service for devices whose user token cannot maintain the approved timezone. macOS retains its root-owned worker and exposes actual registration/approval/heartbeat status; evaluate SMAppService integration against the supported platform floor. Background workers never open authorization dialogs. All components support stop/revoke/uninstall and readback.
5. Use stable app identity/version metadata, Windows publisher signing and macOS Developer ID signing/notarization in the release pipeline. Verify signer identity during signed update installation. Certificate integration requires the owner's credentials through an approved secret destination. A pending certificate question is not evidence of signing completion.
6. Exercise allow/cancel/revoke/policy denial, upgrade identity continuity, restart/sleep/wake and disabled service cases. Use isolated native fixtures for automated tests. Real UAC/TCC prompts require dedicated device evidence and an actual person interacting with the OS prompt; existing mocked dialogs are insufficient evidence.
7. Update stale architecture/support documentation and derive capability presentation from backend data. Notify only on actionable guard failures or revoked permission, with deduplication and a direct return to the affected operation.
8. After optimization acceptance, redesign all desktop screens and the app/tray/navigation icon family. Retain plain explanations, visible per-item results, select-all, one-click reviewed repairs and tutorial. Keep long operations asynchronous with specific phases, cancellation where supported, stable focus/scroll and no duplicate submissions.
9. Verify full Python/JS suites, native packages on Windows + macOS ARM64/Intel, desktop workflows, visual appearance, release contents and public readback. Update the local trial and publish under qudadd/envscope using existing authorization.

## External prerequisites and phase gates

On 2026-10-30 the user confirmed no signing credentials and clarified this is only an open-source project. Formal publisher signing and Apple notarization are optional and no longer delivery gates. Stable identity, honest unsigned-build status, archive integrity and scoped OS authorization remain required. Real device consent observations must remain separately marked pending where unavailable; never count fixture tests as real UAC/TCC evidence. Complete optimization implementation and its automated/native acceptance before the overall UI refresh.

## Invariants

- Tests/development do not alter real networking, timezone, locale, firewall, installed applications, accounts or proxy settings.
- Every actual product mutation discloses effects and requires boolean confirmation; stale or imported reports cannot authorize it.
- Native helpers execute a closed set of operations, use protected files and validate caller/owner, paths, hashes and transaction identity. Never run user-writable Python or upstream scripts with permanent elevation.
- Do not change vendor bytes or licenses; do not run vendor scripts/tests/installers in development.
- Unknown, unsupported, skipped, stale or malformed evidence is never a pass. A successful setting change is not proof of Claude account availability.
- Maintain the user's minimal desktop design and original feature coverage.

## Acceptance evidence

For each requirement, retain a failing regression (when code behavior changes), its passing result, relevant full-suite results and the actual native/runtime evidence. Store a completion matrix distinguishing implemented, fixture-verified, native-verified and external-pending. A green build is not an OS consent result, and a SHA-256 digest is not a publisher signature.

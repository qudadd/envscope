# Permissions and desktop refresh Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete the permission/usability optimizations and their acceptance gates, then deliver the complete minimal desktop UI/icon/interaction upgrade.

**Architecture:** Extend existing collectors, Operations, webview and native helper transactions. Keep ordinary tasks in the user's session, privileged operations narrowly scoped and consent results independently verified.

**Tech Stack:** Python/unittest, JavaScript/node tests, Playwright, native C/OS helpers, PyInstaller, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-10-30-permissions-and-ui-design.md`

## Global Constraints

- Windows/macOS; monochrome/minimal; one main test button; no mobile work.
- No real system changes during development/testing; explicit reviewed boolean confirmation for product writes.
- Preserve vendor, credentials, account recovery, report freshness and unknown-result boundaries.
- User clarified on 2026-10-30: deliver as an open-source project without signing credentials. Formal publisher signatures and Apple notarization are optional, not delivery gates. Keep unsigned build identity and verification honest. Record real authorization device evidence separately from automated fixture evidence.
- Complete optimization acceptance before the overall visual refresh.

## Review Focus

- Permission revoked while the app is in the background: preserve the failed capability and do not repeat consent prompts.
- Target/check selection changes while authorization is pending: discard stale continuation and require a current report.
- User cancels after a partial native transaction: reconcile actual receipts, do not claim nothing changed.
- Service binary/config tampered with or owned by a different user: refuse execution and preserve recovery material.
- App upgrade or sleep/resume changes service state: verify identity/heartbeat before claiming protection.

### Task 1: Truthful collection evidence

**Files:** Create `envscope/observation_errors.py`, `tests/test_inventory_permissions.py`; modify `inventory.py`, `network_facts.py`, `probes.py`, `baseline.py`, `target_environment.py` and their focused tests.

**Interfaces:** `error_evidence(error, operation) -> dict` returns a bounded code and operation without raw diagnostics; `inventory_errors(inventory) -> dict` exposes component errors to report/permission consumers. Existing data keys remain compatible.

- [x] Write regressions for denied DNS/adapter/route reads, unavailable tools, malformed responses, timeout and partial inventory. Assert consumer-visible report/assessment outcomes.
- [x] Run `python -m unittest tests.test_inventory_permissions -v`; observed the expected failures against 0.24.1 behavior.
- [x] Implement structured error propagation and partial-summary handling in the existing collectors/checks.
- [x] Run focused tests and full Python suite: 688 tests, OK, 5 platform skips.
- [x] Commit this independently testable correction and ledger its evidence.

### Task 2: Scoped authorization and automatic continuation

**Files:** Modify `permissions.py`, `operations.py`, `assessment.py`, `web/desktop.mjs`, `web/app.mjs`; create `web/permission_flow.mjs`, `tests/test_permissions.py`, `scripts/permission_flow_smoke.py`.

**Interfaces:** `permission_help` returns capability IDs, scope, affected checks and an OS action while retaining legacy response fields. Frontend `initPermissionFlow({run,operate,recheck,getContext})` owns pending authorization, focus/visibility continuation, cancellation and retry; no permission is granted from a frontend flag.

- [x] Write backend and browser regressions for routed capabilities, cancellation, changed target/selection, missing settings entry and continued denial.
- [x] Observe failures, implement scoped OS actions and bounded continuation with fresh audit/repair preview.
- [x] Classify OS consent/operation outcomes without discarding pending native transactions.
- [x] Verify 697 Python tests (5 platform skips), 19 JavaScript tests, desktop UI at 1024/1280/1440 and Windows/macOS permission workflow fixtures; commit and ledger results. Real OS consent remains separately unmeasured.

### Task 3: Persistent guard authority and actionable notifications

**Files:** Modify `watchdog.py`, `maintenance.py`, `timezone_service.py`, `desktop_runtime.py`, native build scripts; add Windows native timezone service/source, lifecycle adapter and corresponding fixture tests/CI acceptance.

**Interfaces:** Guard preparation exposes per-component capability/authorization state; service adapters implement status/prepare/apply/recover/undo/remove using reviewed plan IDs and protected receipts. UI receives component states from these results rather than inferring authority from a saved baseline.

- [ ] Add regressions proving a matched baseline with insufficient write authority cannot be represented as automatic protection; cover revoke, cancel, tampered files, foreign owner and pending recovery.
- [ ] Implement native Windows timezone service and one-time reviewed installation/update/removal; preserve existing macOS root service behavior and evaluate the supported SMAppService route.
- [ ] Implement deduplicated actionable notifications with a direct return to the failed component.
- [ ] Run isolated native service lifecycle and at least two automatic scheduler cycles on supported CI platforms, with original machine values unchanged; run full suites; commit and ledger evidence.

### Task 4: Release identity, signatures and update verification

**Files:** Modify `scripts/build_desktop.py`, native build scripts, `.github/workflows/desktop.yml`, updater code and release documentation; add signing/publisher verification helpers/tests.

**Interfaces:** Build metadata carries stable `io.qudadd.envscope` identity, semantic/build versions and signed/unsigned mode. Signed release verification requires the configured publisher identity plus archive integrity; missing required signing credentials fail signed release builds.

- [ ] Add executable-package metadata and signer-verification regressions using isolated signed/unsigned/tampered fixtures.
- [ ] Implement Windows publisher signing and Apple Developer ID/notarytool integration through environment/CI secrets, without storing credentials in the repo.
- [ ] Deliver the requested unsigned open-source build, verify identity continuity, and document optional signing configuration. Never label unsigned artifacts as publisher-signed or notarized.
- [ ] Run builds, package verification, update smoke tests and full suites; commit and retain signing/notarization receipts without secrets.

### Task 5: Optimization acceptance and documentation

**Files:** Update `docs/ARCHITECTURE.md`, `docs/DESKTOP_ACCEPTANCE.md`, permission/service docs and backend capability presentation. Create a checked requirement/evidence matrix under `docs/`.

- [ ] Reconcile each of the six source-audit priorities with source, regression and native evidence; fix uncovered behavior before checking it off.
- [ ] Execute the real standard-user/admin consent matrix on dedicated devices, including allow/cancel/revoke, service disable, reboot/sleep and upgrade. Record observed outcomes; leave unavailable device evidence pending.
- [ ] Verify notification deduplication, stop/revoke/uninstall and no loss of current features.
- [ ] Update stale docs and capability descriptions from the actual implementation. Only mark this task complete when all optimization requirements or explicitly revised user requirements are satisfied.

### Task 6: Complete desktop UI, icons and interaction refresh

**Files:** `envscope/web/` screens/styles/modules, native app/tray assets, `desktop_runtime.py`, build icon wiring, walkthrough assets and UI smoke tests.

**Interfaces:** Preserve existing backend capabilities/confirmation contracts. The visual layer renders states supplied by the backend and retains fresh report/repair/guard flows.

- [ ] Confirm Task 5 is complete. Read Impeccable context and the existing design constraints; document the concrete visual system.
- [ ] Implement the complete minimal desktop layout and consistent application/tray/navigation/status icon set, with original licenses for reused assets.
- [ ] Improve phase/progress feedback, keyboard/focus handling, stable selection/scroll, duplicate-operation prevention and recovery affordances across every screen.
- [ ] Run real browser workflows at 1024/1280/1440 widths for Windows/macOS fixtures; inspect screenshots, keyboard access, overflow, empty/loading/error/permission/recovery states and frozen-package icon rendering.
- [ ] Commit the verified UI, asset and interaction changes with documentation.

### Task 7: Full review, native distribution and public delivery

- [ ] Run full Python/JS/syntax/package/desktop workflow and privacy/publication checks for the final source.
- [ ] Request one independent whole-branch code/security review; fix verified findings with regressions.
- [ ] Build and verify Windows x64/macOS ARM64/macOS Intel open-source native distributions, recording their actual signature status.
- [ ] Update the local trial without stopping the user's running application, preserve rollback and publish the reviewed GitHub release under existing authorization.
- [ ] Read back the public release, asset hashes/signers and final local launcher. Audit every explicit requirement before marking the goal complete.

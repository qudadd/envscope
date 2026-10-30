"""Windows/macOS route UI against disposable files and an injected core."""
import json
from pathlib import Path
import tempfile
import threading
from scripts.ui_navigation import open_page, open_details
from playwright.sync_api import expect, sync_playwright

from envscope.operations import Operations
from envscope.service import make_server
from scripts.environment_fixtures import fixture
from tests.test_routing import setup_fixture


def main():
    output = Path('artifacts/routing-ui'); output.mkdir(parents=True, exist_ok=True)
    results = []
    with sync_playwright() as runtime:
        browser = runtime.chromium.launch()
        for system in ('Windows', 'Darwin'):
            with tempfile.TemporaryDirectory() as temp:
                home = Path(temp).resolve()
                store, directory, core, routing = setup_fixture(home, system)
                store._write('learning.private.json', {'completed': True, 'version': 1})
                auditor = lambda *args, **kw: fixture(home, kw.get('baseline_config') or store.settings(), system)
                ops = Operations(store, home, routing=routing, discoverer=lambda: [],
                                 region_lookup=lambda _: {'state': 'unavailable', 'reason': 'fixture'},
                                 environment_reader=lambda: {'platform': system})
                server = make_server(store=store, operations=ops, auditor=auditor)
                thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
                context = browser.new_context(viewport={'width': 1280, 'height': 1000})
                page = context.new_page(); errors = []
                page.on('pageerror', lambda error: errors.append(str(error)))
                page.add_init_script('window.RTCPeerConnection=undefined;')
                page.route('https://**/*', lambda request: request.abort())
                try:
                    page.goto('http://127.0.0.1:' + str(server.server_port), wait_until='networkidle')
                    if page.locator('#learning-skip').is_visible(): page.locator('#learning-skip').click()
                    page.locator('#start').click(); expect(page.locator('#start')).to_be_enabled(timeout=30000)
                    open_page(page, 'upkeep')
                    page.locator('#routing-load').click()
                    expect(page.locator('#routing-group')).to_contain_text('Claude')
                    page.locator('#routing-group').select_option('Claude')
                    page.locator('#routing-prepare').click()
                    expect(page.locator('#routing-plan')).to_contain_text('可能短暂中断')
                    assert not core.calls and not routing.root.exists()
                    page.locator('#routing-plan details').evaluate('(node)=>node.open=true')
                    expect(page.locator('#routing-plan')).to_contain_text('DOMAIN-SUFFIX,claude.ai,Claude')
                    page.locator('#routing-panel').screenshot(path=str(output / (system + '-preview.png')))
                    page.locator('#routing-plan button').click()
                    expect(page.locator('#routing-state')).to_have_text('上次加载已验证', timeout=15000)
                    expect(page.locator('#start')).to_be_enabled(timeout=30000)
                    open_page(page, 'upkeep')
                    page.locator('#routing-restore').click()
                    expect(page.locator('#routing-plan')).to_contain_text('恢复此次路由修改前')
                    assert len(core.calls) == 1
                    page.locator('#routing-plan button').click()
                    expect(page.locator('#routing-state')).to_have_text('已恢复原配置', timeout=15000)
                    expect(page.locator('#start')).to_be_enabled(timeout=30000)
                    open_page(page, 'upkeep')
                    page.locator('#routing-prepare').click()
                    expect(page.locator('#routing-plan button')).to_be_visible()
                    core.fail_load = True
                    page.locator('#routing-plan button').click()
                    expect(page.locator('#routing-state')).to_have_text('需要继续恢复', timeout=15000)
                    expect(page.locator('#start')).to_be_enabled(timeout=30000)
                    open_page(page, 'upkeep')
                    expect(page.locator('#routing-status')).to_have_class('note manual-guidance')
                    expect(page.locator('#routing-prepare')).to_be_disabled()
                    expect(page.locator('#routing-restore')).to_be_enabled()
                    page.locator('#routing-panel').screenshot(path=str(output / (system + '-partial.png')))
                    assert not errors, errors
                    results.append({'platform': system, 'fixture': True, 'preview_before_write': True,
                                    'runtime_readback': True, 'verified_undo': True,
                                    'failed_recovery_is_visible': True, 'auto_retest': True, 'errors': errors})
                finally:
                    context.close(); server.shutdown(); server.server_close(); thread.join(timeout=3)
        browser.close()
    (output / 'results.json').write_text(json.dumps(results, indent=2), encoding='utf-8')
    print(json.dumps(results))


if __name__ == '__main__': main()

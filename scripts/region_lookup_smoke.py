"""Country/city linkage with synthetic IP responses only."""
import json
from pathlib import Path
import tempfile
import threading
import time
from scripts.ui_navigation import open_page, open_details
from playwright.sync_api import expect, sync_playwright
from envscope.operations import Operations
from envscope.service import make_server
from envscope.state import StateStore


def main():
    out=Path('artifacts/region-lookup-ui');out.mkdir(parents=True,exist_ok=True)
    results=[]
    with sync_playwright() as runtime:
        browser=runtime.chromium.launch()
        for system in ('Windows','Darwin'):
            with tempfile.TemporaryDirectory() as tmp:
                home=Path(tmp).resolve();store=StateStore(home/'state')
                fixture={'state':'observed','ip':'8.8.8.8','country':'US','timezone':'America/New_York','reason':'两个模拟来源一致。'}
                delay=[0];calls=[]
                def lookup(params):
                    calls.append(params);value=dict(fixture);time.sleep(delay[0]);return value
                ops=Operations(store,home,discoverer=lambda:[],region_lookup=lookup,
                    environment_reader=lambda:{'platform':system,'locale':'zh-CN','network':{'timezone_id':'China Standard Time'}})
                server=make_server(store=store,operations=ops)
                thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
                context=browser.new_context(viewport={'width':1280,'height':950},locale='zh-CN')
                page=context.new_page();errors=[]
                page.on('pageerror',lambda e:errors.append(str(e)))
                page.route('https://**/*',lambda route:route.abort())
                try:
                    page.goto('http://127.0.0.1:'+str(server.server_port),wait_until='networkidle')
                    page.locator('#learning-skip').click();expect(page.locator('#target-confirm')).to_be_enabled()
                    country=page.locator('#target-form [name=usage_country]')
                    city=page.locator('#target-region-profile');status=page.locator('#target-ip-status')
                    country.fill('US');expect(status).to_contain_text('仅显示 US')
                    assert city.locator('option[value^="us-"]').count()>=29
                    assert city.locator('option').count()==city.locator('option[value^="us-"]').count()+1
                    expect(city).to_have_value('us-new-york')
                    expect(page.locator('#target-form [name=timezone]')).to_have_value('Eastern Standard Time' if system=='Windows' else 'America/New_York')
                    expect(page.locator('#target-form [name=language]')).to_have_value('en-US')
                    city.select_option('us-chicago')
                    expect(page.locator('#target-form [name=timezone]')).to_have_value('Central Standard Time' if system=='Windows' else 'America/Chicago')
                    assert store.settings()['usage_country']=='' and not store.settings()['environment_confirmed']
                    page.screenshot(path=str(out/(system+'-us.png')),full_page=True)
                    fixture.update(country='JP',timezone='Asia/Tokyo')
                    country.fill('JP');expect(status).to_contain_text('仅显示 JP');expect(city).to_have_value('jp-tokyo')
                    assert city.locator('option').count()==2
                    expect(page.locator('#target-form [name=language]')).to_have_value('ja-JP')
                    # A delayed lookup must not replace a manual target edited meanwhile.
                    fixture.update(country='US',timezone='America/New_York');delay[0]=0.5
                    page.locator('#target-read-ip').click();expect(status).to_contain_text('正在按所选')
                    page.locator('#target-form [name=timezone]').fill('Manual timezone')
                    expect(status).to_contain_text('保留手动选择')
                    expect(page.locator('#target-form [name=timezone]')).to_have_value('Manual timezone')
                    # Stale route response is discarded; the queued route is queried after it.
                    delay[0]=0.4;page.locator('#target-read-ip').click();expect(status).to_contain_text('正在按所选')
                    fixture.update(country='JP',timezone='Asia/Tokyo')
                    open_details(page, '#target-connection-options'); page.locator('#target-form [name=connection_mode]').select_option('tun')
                    expect(status).to_contain_text('仅显示 JP');expect(page.locator('#target-confirm')).to_be_enabled()
                    assert calls[-1]['connection_mode']=='tun'
                    fixture.clear();fixture.update(state='conflict',reason='模拟来源国家冲突');delay[0]=0
                    page.locator('#target-read-ip').click();expect(status).to_contain_text('尚未根据 IP 匹配')
                    expect(country).to_have_value('JP')
                    assert not errors and page.evaluate('document.documentElement.scrollWidth<=innerWidth')
                    results.append({'platform':system,'country_filter':True,'timezone_language':True,'stale_response_rejected':True,'manual_edit_preserved':True,'real_network':False,'user_settings_changed':False})
                finally:
                    context.close();server.shutdown();server.server_close();thread.join(3)
        browser.close()
    (out/'results.json').write_text(json.dumps(results,indent=2),encoding='utf-8');print(json.dumps(results))


if __name__=='__main__':main()

"""Exercise an isolated native window and tray; never start user diagnostics."""
import json
from pathlib import Path
import platform
import sys
import tempfile
import threading
import time
from unittest.mock import Mock


def main(output=None):
    import webview
    from envscope import __release__
    from envscope.desktop_runtime import DesktopRuntime
    from envscope.service import make_server
    from envscope.state import StateStore
    from envscope.operations import Operations
    from envscope.legacy import LegacyBridge
    result = {"platform": platform.system(), "release": __release__, "native_window": False, "tray": False, "close_hides": False, "reopened": False, "quit": False, "network_probes": False, "user_data_changed": False}
    with tempfile.TemporaryDirectory(prefix='envscope-native-test-') as directory:
        directory = Path(directory).resolve()
        store = StateStore(Path(directory) / 'state')
        store._write('desktop-preferences.private.json', {'check_updates': False})
        operations = Operations(store, directory, discoverer=lambda: [], region_lookup=lambda params: {'state':'unavailable','reason':'Offline native fixture'}, legacy=LegacyBridge(home=directory, runner=Mock(side_effect=AssertionError('No vendor execution'))),
                                environment_reader=lambda: {'platform':platform.system(),'locale':'en-US','network':{'timezone_id':'UTC'}})
        assert operations.legacy._vendor_integrity()['verified'], 'Bundled upstream bytes and filenames must survive installation'
        from .browser_sessions import SessionStore,validate_fixture_root
        from .accounts import AccountError
        try:
            validate_fixture_root(Path.home())
        except AccountError:
            pass
        else:
            raise AssertionError('Browser fixture entry must refuse real home')
        sessions = SessionStore(directory/'.envscope/browser-sessions',running=lambda _:False,alive=lambda *_:False,pause=lambda _:None)
        browser_profile = sessions.create('a'*32)
        (browser_profile/'Cookies').write_bytes(b'FROZEN_PRIVATE_BROWSER_FIXTURE')
        sessions.launched('a'*32,Mock(pid=123456))
        assert sessions.cleanup()['removed']==1
        result.update(browser_session_fixture=True,native_browser_registry=True)
        from .legacy_components import ComponentMigration
        from .legacy_software import SoftwareCleanup
        class NoLegacyJobs:
            fixture=True
            def snapshot(self):
                return {'format':1,'system':platform.system(),'actor':'frozen-fixture',
                        'rows':[{'id':'guard','owned':True,'present':False,'registered':False,'running':False,'enabled':False}]}
            def status(self):return {'id':'','state':'not_configured'}
            def execute(self,*args):raise AssertionError('Frozen software fixture must not modify OS jobs')
        software=SoftwareCleanup(directory,ComponentMigration(store,directory,io=NoLegacyJobs()),
                                 processes=lambda paths:False,transaction_lock=lambda:operations.accounts._lock())
        old_program=software.paths['core'];old_program.parent.mkdir(parents=True,exist_ok=True)
        body=b'# claude-switch checkdetail FROZEN SELF AUTHORED FIXTURE\n'
        old_program.write_bytes(body)
        program_roles=['core'];created_shortcut=None;created_ui=None
        result['native_unicode_shortcut']='not_applicable'
        if platform.system()=='Windows':
            import ctypes,os
            from .windows_shortcut import _Shortcut,read_shortcut
            created_shortcut=software.paths['shortcut'];created_shortcut.parent.mkdir(parents=True)
            created_ui=software.paths['ui'];created_ui.write_bytes(b'# claude-switcher Window FROZEN INERT FIXTURE\n')
            target=str(Path(os.environ['SystemRoot'])/'System32/WindowsPowerShell/v1.0/powershell.exe')
            arguments='-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "'+str(created_ui)+'"'
            with _Shortcut() as link:
                link.check(link.call(link.link,20,[ctypes.c_wchar_p],target))
                link.check(link.call(link.link,11,[ctypes.c_wchar_p],arguments))
                link.check(link.call(link.file,6,[ctypes.c_wchar_p,ctypes.c_int],str(created_shortcut),1))
            assert read_shortcut(created_shortcut)['args']==arguments
            program_roles+=['ui','shortcut']
        plan=software.prepare(program_roles);assert plan['state']=='planned',plan
        value=software.apply(plan['plan_id'],True);assert value['state']=='completed',value
        assert not old_program.exists()
        software=SoftwareCleanup(directory,software.components,processes=lambda paths:False)
        plan=software.prepare(restore=True);assert plan['state']=='planned',plan
        value=software.apply(plan['plan_id'],True);assert value['state']=='restored',value
        assert old_program.read_bytes()==body
        if created_shortcut:
            assert read_shortcut(created_shortcut)['args']==arguments
            created_shortcut.unlink();created_ui.unlink()
            result['native_unicode_shortcut']=True
        old_program.unlink()  # Only the file created immediately above.
        result['native_software_file_roundtrip']=True
        # Frozen imports, persisted consent and ZIP privacy on disposable data.
        import base64
        from io import BytesIO
        from zipfile import ZipFile
        operations.diagnostics.record('audit','completed')
        config=operations.run('check-config-save',{'disabled':['webrtc','ecosystem'],'logging':False})
        assert config['state']=='completed'
        assert StateStore(store.root).settings()['check_config']['logging'] is False
        exported=operations.run('diagnostics-export',{},True)
        with ZipFile(BytesIO(base64.b64decode(exported['archive']['data']))) as bundle:
            assert set(bundle.namelist())=={'summary.json','commands.jsonl','README.txt'}
            assert not bundle.read('commands.jsonl')
        result['native_diagnostics_export']=True
        # Exercise the packaged cryptography/OpenSSL runtime on disposable data.
        manager = operations.accounts
        manager.accounts_dir.mkdir(parents=True,exist_ok=True)
        manager.data_dir.mkdir(parents=True)
        (manager.state_dir/manager.current_filename).write_text('A')
        archived = manager.accounts_dir/'B'
        archived.mkdir()
        (archived/'fixture.txt').write_text('NATIVE_ARCHIVE_FIXTURE',encoding='utf-8')
        encrypted = Path(directory)/'native.envsnap'
        operations.archives.export('B',str(encrypted),'native-fixture-password-123')
        operations.archives.import_archive(str(encrypted),'C','native-fixture-password-123')
        assert (manager.accounts_dir/'C/fixture.txt').read_bytes()==(archived/'fixture.txt').read_bytes()
        assert b'NATIVE_ARCHIVE_FIXTURE' not in encrypted.read_bytes()
        assert not list((Path(directory)/'.envscope/archive-work').iterdir())
        import cryptography
        result.update(encrypted_archive_roundtrip=True,cryptography_version=cryptography.__version__)
        # Independent legacy-format path in the frozen runtime, still fixtures.
        csnap = directory/'native.csnap'
        operations.run('archive-export', {'slot':'B','file':str(csnap),'password':'fixture8','format':'csnap'}, True)
        archived_file = archived/'fixture.txt'
        expected = archived_file.read_bytes()
        archived_file.unlink()
        archived.rmdir()
        operations.run('archive-import', {'slot':'B','file':str(csnap),'password':'fixture8','format':'csnap'}, True)
        assert archived_file.read_bytes() == expected
        assert csnap.read_bytes().startswith(b'CSNAP001')
        assert not list((directory/'.envscope/csnap-work').iterdir())
        result['native_csnap_roundtrip'] = True
        result['native_dmg_roundtrip'] = 'not_applicable'
        result['native_timezone_worker'] = 'not_applicable'
        result['native_network_worker'] = 'not_applicable'
        result['native_components_worker'] = 'not_applicable'
        result['native_language_bindings']='not_applicable'
        result['native_pipe_transport']='not_applicable'
        result['native_wireguard_bindings']='not_applicable'
        if platform.system()=='Windows':
            from .timezone_service import bundle_worker
            import subprocess
            worker=bundle_worker(cache=directory/'native-timezone-cache',system='Windows')
            info=json.loads(subprocess.check_output([worker['path'],'--version'],timeout=10))
            assert info=={'format':1,'release':__release__,'fixture':False}
            result['native_timezone_worker']=True
            from .wireguard import WindowsServices, command_identity, PREFIX
            path = 'C:\\Program Files\\WireGuard\\wireguard.exe'
            args = WindowsServices().argv('"'+path+'" /tunnelservice "C:\\EnvScopeFixture.conf"')
            result['native_wireguard_bindings'] = command_identity(args, PREFIX+'EnvScopeFixture', [path]) == path
            assert result['native_wireguard_bindings']
            from .windows_pipe import validate_pipe
            assert validate_pipe(r'\\.\pipe\envscope-frozen-fixture')==r'\\.\pipe\envscope-frozen-fixture'
            result['native_pipe_transport']=True
        if platform.system() == 'Darwin':
            from .mac_preferences import ClaudePreferences
            assert callable(ClaudePreferences().read)  # Load OS symbols; do not write any app preference.
            result['native_language_bindings']=True
            from .timezone_service import bundle_worker
            import subprocess
            worker=bundle_worker(cache=directory/'native-timezone-cache')
            info=json.loads(subprocess.check_output([worker['path'],'--version'],timeout=10))
            assert info=={'format':1,'release':__release__,'fixture':False}
            result['native_timezone_worker']=True
            network=bundle_worker(cache=directory/'native-network-cache',component='network')
            info=json.loads(subprocess.check_output([network['path'],'--version'],timeout=10))
            assert info=={'format':1,'release':__release__,'fixture':False}
            result['native_network_worker']=True
            components=bundle_worker(cache=directory/'native-components-cache',component='components')
            info=json.loads(subprocess.check_output([components['path'],'--version'],timeout=10))
            assert info=={'format':1,'release':__release__,'fixture':False}
            result['native_components_worker']=True
            # Exercise real hdiutil from the frozen application, only in this
            # disposable home. No real Claude credentials or system keychain.
            import shutil
            image = directory/'native.dmg'
            operations.dmg_archives.export('B',str(image),'frozen-dmg-fixture-123')
            shutil.rmtree(archived)
            operations.dmg_archives.import_archive(str(image),'B','frozen-dmg-fixture-123')
            assert (archived/'fixture.txt').read_bytes() == b'NATIVE_ARCHIVE_FIXTURE'
            assert not operations.dmg_archives.status()['pending']
            result['native_dmg_roundtrip'] = True
        import psutil
        result['psutil_version']=psutil.__version__
        # The shipped account transaction/recovery code touches only this fixture.
        manager.stop_app = lambda: True
        manager.launch_app = None
        manager.force_stop_app = Mock(side_effect=AssertionError('No real processes'))
        (manager.data_dir/'Local State').write_bytes(b'NATIVE_ACCOUNT_A')
        manager.switch('B', lambda: True)
        assert (manager.data_dir/'fixture.txt').read_bytes() == b'NATIVE_ARCHIVE_FIXTURE'
        assert not (manager.data_dir/'Local State').exists()
        manager.switch('A', lambda: True)
        assert (manager.data_dir/'Local State').read_bytes() == b'NATIVE_ACCOUNT_A'
        result['account_volume_roundtrip'] = True
        class Interrupted(BaseException):
            pass
        from unittest.mock import patch
        with patch.object(manager, '_write_current', side_effect=Interrupted()):
            try:
                manager.switch('B', lambda: True)
            except Interrupted:
                pass
            else:
                raise AssertionError('Fixture failed to interrupt account exchange')
        recovery = manager.recovery.plan()
        assert recovery['state'] == 'planned'
        assert manager.recovery.apply(recovery['plan_id'], True)['state'] == 'completed'
        assert (manager.data_dir/'Local State').read_bytes() == b'NATIVE_ACCOUNT_A'
        assert not manager._pending()
        result['account_recovery'] = True
        server = make_server(store=store, operations=operations, auditor=Mock(side_effect=AssertionError('No public probes')))
        window = webview.create_window('EnvScope isolated test', 'http://127.0.0.1:' + str(server.server_port), width=1040, height=760, hidden=True)
        runtime = DesktopRuntime(server, window)
        assert runtime.updates.status()['current'] == __release__, 'Updater release must match the installed binary'
        operations.desktop_runtime = runtime
        window.events.closing += runtime.closing
        runtime.start_tray()
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        errors = []
        def read_js(expression):
            # evaluate_js wraps code in eval, which our CSP deliberately blocks.
            # Both supported native renderers return run_js string results.
            value = window.run_js('JSON.stringify(' + expression + ')')
            return json.loads(value) if isinstance(value, str) else None
        def exercise():
            try:
                deadline = time.monotonic() + 25
                while time.monotonic() < deadline:
                    if read_js("document.getElementById('native-preferences')?.hidden === false"):
                        break
                    time.sleep(0.2)
                else:
                    result['page_state'] = read_js("({ready:document.readyState, text:document.body.innerText.slice(0,1500), scripts:[...document.scripts].map(s=>s.src)})")
                    raise AssertionError('Native UI did not connect to the fixture server')
                result['native_window'] = True
                result['account_volume_controls'] = read_js("!!document.getElementById('account-recovery-check') && !!document.getElementById('account-force-close')")
                assert result['account_volume_controls']
                result['select_all_control'] = read_js("document.getElementById('checks-select-all')?.textContent === '全选' && !!document.getElementById('checks-repair') && !!document.getElementById('target-region-profile')")
                assert result['select_all_control'], 'Selective checks and region presets must ship in the native UI'
                result['watchdog_controls']=read_js("!!document.getElementById('upkeep-guard-timezone') && !!document.getElementById('upkeep-guard-proxy')")
                result['ip_lookup_control']=read_js("!!document.getElementById('target-read-ip')")
                assert result['watchdog_controls'] and result['ip_lookup_control']
                result['process_guard_controls']=read_js("!!document.getElementById('process-guard-prepare') && !!document.getElementById('process-guard-stop')")
                assert result['process_guard_controls']
                result['routing_controls']=read_js("!!document.getElementById('routing-prepare') && !!document.getElementById('routing-restore')")
                result['system_network_controls']=read_js("!!document.getElementById('network-all') && !!document.getElementById('network-restore') && !!document.getElementById('network-dns')")
                assert result['system_network_controls']
                result['client_repair_controls']=read_js("!!document.getElementById('client-prepare') && !!document.getElementById('client-restore') && !!document.getElementById('client-force')")
                result['client_language_controls']=read_js("!!document.getElementById('language-prepare') && !!document.getElementById('language-restore')")
                result['wireguard_controls']=read_js("!!document.getElementById('target-wireguard-read') && !!document.querySelector('#target-form select[name=client] option[value=wireguard]') && !!document.querySelector('#target-form select[name=wireguard_service]')")
                assert result['wireguard_controls']
                assert result['client_repair_controls'] and result['client_language_controls']
                from .routing_config import load_yaml, update_yaml_rules, rule_strings
                pinned = rule_strings('Fixture', 'proxy')
                result['routing_yaml'] = list(load_yaml(update_yaml_rules(b'rules: []\n', pinned))[1]['rules']) == pinned
                assert result['routing_controls'] and result['routing_yaml']
                assert runtime.ready.wait(5), 'Tray did not initialize'
                result['tray'] = True
                ids = read_js("[...document.querySelectorAll('[id]')].map(n=>n.id)")
                assert len(ids) == len(set(ids)), 'Duplicate DOM IDs'
                # Exercise the actual menu callback and its CSP-compatible JS.
                runtime.icon.menu.items[1](runtime.icon)
                assert read_js("document.getElementById('page-settings').hidden === false")
                result['tray_settings'] = True
                assert runtime.closing() is False
                result['close_hides'] = True
                runtime.show()
                result['reopened'] = True
                runtime.server.audit_lock.acquire()
                try:
                    assert runtime.quit() is False
                finally:
                    runtime.server.audit_lock.release()
                assert runtime.quit() is True
                result['quit'] = True
            except BaseException as error:
                errors.append(type(error).__name__ + ': ' + str(error))
                runtime.quitting = True
                window.destroy()
        try:
            webview.start(exercise, gui='edgechromium' if platform.system() == 'Windows' else 'cocoa', debug=False, private_mode=True)
        finally:
            runtime.close()
            server.shutdown()
            server.server_close()
            thread.join(3)
        result['errors'] = errors
        destination = Path(output) if output else Path('artifacts/native-smoke.json')
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(result, indent=2), encoding='utf-8')
        if sys.stdout:
            print(json.dumps(result))
        if errors:
            raise SystemExit(1)


if __name__ == '__main__':
    main()

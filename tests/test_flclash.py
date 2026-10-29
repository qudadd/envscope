"""FlClash support uses fixed app identities and fixture-only lifecycle calls."""
from datetime import datetime, timezone
from pathlib import Path
import plistlib
import tempfile
import unittest

from envscope.baseline import proxy_runtime
from envscope.client_apps import discover_apps
from envscope.client_repair import ClientRepair, NativeClientIO
from envscope.process_guard import health
from envscope.state import StateStore
from envscope.target_environment import fingerprint
from envscope.watchdog import proxy_apps
from test_client_repair import ClientFixture


class FlClashTests(unittest.TestCase):
    def test_windows_discovery_and_approved_watchdog_find_installed_flclash(self):
        with tempfile.TemporaryDirectory() as directory:
            home=Path(directory).resolve();binary=home/'local/Programs/FlClash/FlClash.exe'
            binary.parent.mkdir(parents=True);binary.write_bytes(b'NOT_AN_EXECUTABLE_FIXTURE')
            env={'LOCALAPPDATA':str(home/'local'),'ProgramFiles':str(home/'programs')}
            apps=discover_apps(home,'Windows',env,registry=lambda:[])
            self.assertEqual(len(apps),1);self.assertEqual(apps[0]['mode'],'flclash')
            self.assertEqual([r['path'] for r in proxy_apps(home,'Windows',env)],[str(binary)])

    def test_mac_discovery_reads_the_bundle_executable(self):
        with tempfile.TemporaryDirectory() as directory:
            home=Path(directory).resolve();contents=home/'Applications/FlClash.app/Contents'
            (contents/'MacOS').mkdir(parents=True)
            (contents/'Info.plist').write_bytes(plistlib.dumps({'CFBundleExecutable':'FlClash'}))
            binary=contents/'MacOS/FlClash';binary.write_bytes(b'NOT_EXECUTABLE')
            apps=discover_apps(home,'Darwin',{},mac_roots=[home/'Applications'])
            self.assertEqual(len(apps),1);self.assertEqual(apps[0]['mode'],'flclash')
            self.assertEqual(apps[0]['path'],str(binary))

    def test_only_flclash_core_satisfies_selected_kernel_condition(self):
        from envscope.model import Status
        self.assertEqual(proxy_runtime({'network':{'known_clients':['FlClashCore']}},{'client':'flclash'}).status,Status.PASS)
        self.assertNotEqual(proxy_runtime({'network':{'known_clients':['FlClash']}},{'client':'flclash'}).status,Status.PASS)
        baseline={'mode':'tun','client':'flclash','interface':'fixture-tun'}
        observed={'unreadable':False,'interfaces':[{'name':'fixture-tun','up':True}],'clients':['mihomo']}
        self.assertFalse(health(baseline,observed,None)[0])
        observed['clients']=['flclashcore'];self.assertTrue(health(baseline,observed,None)[0])

    def test_start_restart_restore_and_unsupported_tun_never_write_verge_preferences(self):
        with tempfile.TemporaryDirectory() as directory:
            home=Path(directory).resolve();store=StateStore(home/'state')
            store.save_settings({'usage':'desktop','connection_mode':'tun','client':'flclash','usage_country':'US'},confirm_environment=True)
            io=ClientFixture(home);io.app.update(mode='flclash',label='FlClash');io.running=False
            before=io.preference.read_bytes();seconds=[0]
            manager=ClientRepair(store,io,clock=lambda:seconds[0],sleeper=lambda n:seconds.__setitem__(0,seconds[0]+n))
            report={'report_id':'fixture','created_at':datetime.now(timezone.utc).isoformat(),'mode':'one-click-desktop',
                    'diagnosis':{},'findings':[{'id':'target.region','status':'pass'}],'environment':{'fingerprint':fingerprint(store.settings())}}
            plan=manager.prepare(report)
            self.assertEqual(plan['state'],'planned');self.assertEqual(io.calls,[])
            result=manager.apply(plan['plan_id'],True,report)
            self.assertEqual(result['state'],'completed');self.assertTrue(result['needs_retest'])
            self.assertEqual(io.preference.read_bytes(),before)
            restored=ClientRepair(store,io,clock=lambda:seconds[0],sleeper=lambda n:seconds.__setitem__(0,seconds[0]+n))
            restore=restored.prepare_restore();self.assertEqual(restore['state'],'planned')
            self.assertEqual(restored.restore(restore['plan_id'],True)['state'],'completed')
            self.assertEqual(io.preference.read_bytes(),before)
            with self.assertRaises(ValueError):NativeClientIO(home,'Windows').context(io.app)

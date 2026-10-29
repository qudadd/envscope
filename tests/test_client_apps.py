"""Injected process and filesystem fixtures; no installed app is launched."""
from copy import deepcopy
from pathlib import Path
import plistlib
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

from envscope.client_apps import AppLifecycle,discover_apps,file_hash


class ProcessFixture:
    class Error(Exception):pass
    class NoSuchProcess(Error):pass
    def __init__(self,path):
        self.rows={7:{'pid':7,'name':Path(path).name,'exe':str(path),'create_time':1000.25,'username':'fixture\\owner'}}
        self.calls=[];self.replace=False
    def process_iter(self,*args,**kwargs):return [SimpleNamespace(info=deepcopy(r)) for r in self.rows.values()]
    def Process(self,pid=None):
        if pid is None:return SimpleNamespace(username=lambda:'fixture\\owner')
        if pid not in self.rows:raise self.NoSuchProcess()
        row=self.rows[pid];born=row['create_time'];parent=self
        class Process:
            def create_time(self):return row['create_time']
            def username(self):return row['username']
            def exe(self):return row['exe']
            def terminate(self):
                if parent.replace:
                    parent.rows[pid]={**row,'create_time':born+1};raise parent.NoSuchProcess()
                parent.calls.append(('terminate',pid,born));parent.rows.pop(pid,None)
            def kill(self):
                parent.calls.append(('kill',pid,born));parent.rows.pop(pid,None)
        return Process()


class ClientAppTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.home=Path(self.temp.name).resolve();self.path=self.home/'Clash Verge/clash-verge.exe'
        self.path.parent.mkdir();self.path.write_bytes(b'NEVER_EXECUTE_APP_FIXTURE')
        self.app={'id':'fixture-app','mode':'clash-verge','label':'Clash Verge','path':str(self.path),'sha256':file_hash(self.path)}
        self.ps=ProcessFixture(self.path);self.seconds=0
        def sleep(n):self.seconds+=n
        self.runner=Mock(return_value=SimpleNamespace(returncode=0));self.launcher=Mock()
        self.io=AppLifecycle(self.home,'Darwin',self.ps,self.runner,self.launcher,Mock(),sleep,lambda:self.seconds)

    def test_windows_discovery_accepts_known_registry_path_without_command_parsing(self):
        paths=lambda:[('clash-verge','Clash Verge',self.path,None)]
        result=discover_apps(self.home,'Windows',{},paths)
        self.assertEqual(len(result),1);self.assertEqual(result[0]['path'],str(self.path))
        self.assertNotIn('sha256',result[0]);self.assertFalse(self.runner.called or self.launcher.called)

    def test_macos_discovery_reads_bundle_executable_and_rejects_traversal(self):
        app=self.home/'Applications/Shadowrocket.app/Contents';(app/'MacOS').mkdir(parents=True)
        (app/'MacOS/Rocket').write_bytes(b'NOT_A_REAL_APP')
        (app/'Info.plist').write_bytes(plistlib.dumps({'CFBundleExecutable':'Rocket'}))
        result=discover_apps(self.home,'Darwin',{},mac_roots=[self.home/'Applications'])
        self.assertEqual(len(result),1);self.assertEqual(result[0]['mode'],'shadowrocket')
        for invalid in ('../outside','nested/name','x\0y',None):
            value={} if invalid is None else {'CFBundleExecutable':invalid}
            (app/'Info.plist').write_bytes(plistlib.dumps(value,fmt=plistlib.FMT_BINARY))
            self.assertEqual(discover_apps(self.home,'Darwin',{},mac_roots=[self.home/'Applications']),[])

    def test_normal_exit_is_a_request_then_independent_readback(self):
        def quit(pid):self.ps.rows.pop(pid,None);return True
        self.io.mac_quit=Mock(side_effect=quit)
        self.assertEqual(self.io.stop(self.app),{'stopped':True,'forced':False})
        self.io.mac_quit.assert_called_once_with(7);self.assertEqual(self.ps.calls,[])

    def test_request_acceptance_or_timeout_never_implies_exit(self):
        self.io.mac_quit=Mock(return_value=True)
        self.assertEqual(self.io.stop(self.app),{'stopped':False,'forced':False})
        self.assertIn(7,self.ps.rows);self.assertEqual(self.ps.calls,[])
        for value in (1,'true',None):
            with self.assertRaises(ValueError):self.io.stop(self.app,value)

    def test_force_is_explicit_and_a_replacement_pid_is_not_killed(self):
        result=self.io.stop(self.app,True)
        self.assertEqual(result,{'stopped':True,'forced':True});self.assertEqual(self.ps.calls,[('terminate',7,1000.25)])
        self.setUp();self.ps.replace=True
        result=self.io.stop(self.app,True)
        self.assertFalse(result['stopped']);self.assertEqual(self.ps.rows[7]['create_time'],1001.25)
        self.assertEqual(self.ps.calls,[])

    def test_other_users_and_same_names_at_other_paths_are_untouched(self):
        self.ps.rows[7]['username']='somebody_else'
        self.assertEqual(self.io.stop(self.app),{'stopped':True,'forced':False})
        self.assertIn(7,self.ps.rows);self.io.mac_quit.assert_not_called()
        self.ps.rows[7]['username']='fixture\\owner';self.ps.rows[7]['exe']=str(self.home/'other/clash-verge.exe')
        self.assertEqual(self.io.stop(self.app),{'stopped':True,'forced':False});self.assertIn(7,self.ps.rows)

    def test_new_instances_and_unreadable_processes_stop_before_force(self):
        self.ps.rows[7]['exe']=None
        with self.assertRaises(ValueError):self.io.stop(self.app,True)
        self.assertEqual(self.ps.calls,[])
        self.setUp()
        def quit(pid):self.ps.rows[pid]['create_time']+=1
        self.io.mac_quit=Mock(side_effect=quit)
        with self.assertRaises(ValueError):self.io.stop(self.app,True)
        self.assertEqual(self.ps.calls,[])

    def test_binary_change_blocks_exit_and_launch_before_any_request(self):
        self.path.write_bytes(b'CHANGED_APP_FIXTURE')
        with self.assertRaises(ValueError):self.io.stop(self.app,True)
        with self.assertRaises(ValueError):self.io.start(self.app)
        self.io.mac_quit.assert_not_called();self.assertFalse(self.launcher.called)

    def test_launch_request_is_not_a_running_or_tun_claim(self):
        self.ps.rows.clear();self.io.system='Windows'
        result=self.io.start(self.app)
        self.assertEqual(result,{'requested':True,'already_running':False})
        self.assertEqual(self.launcher.call_args.args[0],[str(self.path)])
        self.assertFalse(self.io.snapshot(self.app)['processes'])


if __name__=='__main__':unittest.main()

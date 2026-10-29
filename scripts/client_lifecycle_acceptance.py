"""Actual user GUI lifecycle on a compiled, disposable application only."""
import json
import os
from pathlib import Path
import platform
import plistlib
import subprocess
import tempfile
import time
import uuid

from envscope import __release__
from envscope.client_apps import AppLifecycle,file_hash


def build_fixture(root,system):
    if system=='Darwin':
        app=root/'EnvScopeFixture.app';contents=app/'Contents';(contents/'MacOS').mkdir(parents=True)
        (contents/'Info.plist').write_bytes(plistlib.dumps({'CFBundleIdentifier':'io.qudadd.envscope.fixture.'+uuid.uuid4().hex,
            'CFBundleExecutable':'EnvScopeProbe','CFBundleName':'EnvScope Lifecycle Fixture','CFBundlePackageType':'APPL',
            'LSUIElement':True}))
        source=root/'fixture.m'
        source.write_text(r'''#import <Cocoa/Cocoa.h>
static NSString *folder(void){return [[[NSBundle mainBundle] bundlePath] stringByDeletingLastPathComponent];}
static NSString *file(NSString *name){return [folder() stringByAppendingPathComponent:name];}
@interface FixtureDelegate : NSObject <NSApplicationDelegate> @end
@implementation FixtureDelegate
-(void)applicationDidFinishLaunching:(NSNotification *)notification {
 (void)notification;[@"ready" writeToFile:file(@"ready") atomically:YES encoding:NSUTF8StringEncoding error:nil];
}
-(NSApplicationTerminateReply)applicationShouldTerminate:(NSApplication *)sender {
 (void)sender;if([[NSFileManager defaultManager] fileExistsAtPath:file(@"ignore-close")])return NSTerminateCancel;
 [@"normal" writeToFile:file(@"normal-exit") atomically:YES encoding:NSUTF8StringEncoding error:nil];return NSTerminateNow;
}
@end
int main(void){@autoreleasepool{NSApplication *app=[NSApplication sharedApplication];
 FixtureDelegate *delegate=[FixtureDelegate new];[app setDelegate:delegate];
 [app setActivationPolicy:NSApplicationActivationPolicyAccessory];[app run];}return 0;}
''')
        binary=contents/'MacOS/EnvScopeProbe'
        subprocess.run(['/usr/bin/xcrun','clang','-fobjc-arc','-mmacosx-version-min=12.0','-framework','Cocoa',str(source),'-o',str(binary)],check=True,capture_output=True)
        subprocess.run(['/usr/bin/codesign','--force','--deep','--sign','-',str(app)],check=True,capture_output=True)
        return binary,str(app)
    from envscope.system_network_windows import powershell,quote
    source=root/'fixture.cs';binary=root/'EnvScopeProbe.exe'
    source.write_text(r'''using System;using System.IO;using System.Windows.Forms;
class Fixture : Form {
 static string Folder=Path.GetDirectoryName(Application.ExecutablePath);
 static string FileName(string name){return Path.Combine(Folder,name);}
 public Fixture(){Text="EnvScope Lifecycle Fixture";Shown+=(s,e)=>File.WriteAllText(FileName("ready"),"ready");}
 protected override void OnFormClosing(FormClosingEventArgs e){
  if(File.Exists(FileName("ignore-close"))){e.Cancel=true;Hide();}else File.WriteAllText(FileName("normal-exit"),"normal");
  base.OnFormClosing(e);
 }
 [STAThread] static void Main(){Application.EnableVisualStyles();Application.Run(new Fixture());}
}''')
    code=("$ErrorActionPreference='Stop';$env:PSModulePath=Join-Path ([Environment]::GetFolderPath('Windows')) 'System32/WindowsPowerShell/v1.0/Modules';"
          "Add-Type -Path "+quote(source)+" -ReferencedAssemblies System.Windows.Forms,System.Drawing -OutputAssembly "+quote(binary)+" -OutputType WindowsApplication")
    result=subprocess.run([powershell(),'-NoProfile','-NonInteractive','-Command',code],capture_output=True,timeout=40)
    if result.returncode:raise RuntimeError('Owned lifecycle fixture failed to compile: '+result.stderr.decode('utf-8',errors='replace')[-1000:])
    return binary,None


def main():
    system=platform.system()
    if system not in ('Windows','Darwin') or os.environ.get('GITHUB_ACTIONS')!='true' or os.environ.get('ENVSCOPE_CLIENT_ACCEPTANCE')!='1':
        raise SystemExit('Application lifecycle fixture requires opted-in disposable desktop CI')
    output=Path('artifacts/client-lifecycle');output.mkdir(parents=True,exist_ok=True)
    proof={'platform':system,'architecture':platform.machine(),'release':__release__,'fixture':True,
           'real_proxy_changed':False,'real_claude_changed':False,'real_network_changed':False,'state':'started'}
    with tempfile.TemporaryDirectory(prefix='envscope-client-fixture-') as directory:
        root=Path(directory).resolve();binary,bundle=build_fixture(root,system)
        app={'id':'owned-ci-fixture','mode':'fixture','label':'EnvScope lifecycle fixture',
             'path':str(binary),'bundle':bundle,'sha256':file_hash(binary)}
        io=AppLifecycle(system=system)
        def wait(predicate):
            deadline=time.monotonic()+20
            while time.monotonic()<deadline:
                if predicate():return
                time.sleep(.2)
            raise AssertionError('Owned lifecycle fixture did not reach expected state')
        try:
            assert io.start(app)['requested']
            wait(lambda:(root/'ready').exists() and bool(io.snapshot(app)['processes']))
            assert io.stop(app)=={'stopped':True,'forced':False}
            assert (root/'normal-exit').read_text()=='normal';proof['normal_exit_and_readback']=True
            (root/'ready').unlink();(root/'normal-exit').unlink();(root/'ignore-close').touch()
            assert io.start(app)['requested']
            wait(lambda:(root/'ready').exists() and bool(io.snapshot(app)['processes']))
            original=io.snapshot(app)['processes']
            assert io.stop(app)=={'stopped':False,'forced':False}
            assert io.snapshot(app)['processes']==original and not (root/'normal-exit').exists()
            proof['declined_exit_preserves_process']=True
            assert io.stop(app,True)=={'stopped':True,'forced':True}
            assert not (root/'normal-exit').exists();proof['explicit_force_and_readback']=True
            try:io.start({**app,'sha256':'0'*64})
            except ValueError:proof['changed_binary_rejected']=True
            else:raise AssertionError('Different binary approval must not launch')
            proof['state']='passed'
        finally:
            # The only target executable is inside this unique owned fixture.
            assert binary.is_relative_to(root) and root.name.startswith('envscope-client-fixture-')
            try:io.stop(app,True)
            finally:
                proof['fixture_stopped']=not io.snapshot(app)['processes']
                (output/'result.json').write_text(json.dumps(proof,indent=2))
            assert proof['fixture_stopped']
    proof['fixture_removed']=not root.exists();assert proof['fixture_removed']
    (output/'result.json').write_text(json.dumps(proof,indent=2))
    print(json.dumps(proof))


if __name__=='__main__':main()

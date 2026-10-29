"""CI only: unique owned jobs and harmless scripts; no vendor/network/account actions."""
import base64
import hashlib
import json
import os
from pathlib import Path
import platform
import plistlib
import shutil
import subprocess
import tempfile
import time
import uuid

from envscope.component_inventory import Layout
from envscope.legacy_components import ComponentMigration
from envscope.state import StateStore


def command(args, **kwargs):
    v = subprocess.run(args, capture_output=True, timeout=45, **kwargs)
    if v.returncode: raise RuntimeError('owned component fixture command failed: '+Path(args[0]).name+' '+str(v.returncode)+' '+v.stderr.decode(errors='replace')[-1800:])
    return v


def windows(home, result):
    from envscope.components_windows import WindowsComponents
    from envscope.system_network_windows import powershell, quote
    marker = 'EnvScopeLegacyFixture'+uuid.uuid4().hex
    source = home/'.claude-switcher/claude-bodyguard.ps1'; source.parent.mkdir(parents=True)
    source.write_text('while ($true) { Start-Sleep -Milliseconds 200 }\n', encoding='utf-8')
    preserve = home/'.claude-switcher/accounts/A/fixture.private.bin'; preserve.parent.mkdir(parents=True); preserve.write_bytes(b'ACCOUNT_FIXTURE_ONLY')
    layout = Layout(home, 'Windows', fixture={'root': home/'privileged/receipt', 'task': marker,
        'labels': {}, 'daemons': home/'not-used', 'scripts': home/'not-used'})
    shell = powershell()
    def runner(args, **kwargs):
        # The hosted actor is already elevated. Execute the identical encoded
        # transaction directly so CI retains its failure output; this does not
        # simulate or claim a Windows UAC interaction.
        if kwargs.get('input'):
            encoded = kwargs.pop('input').decode('ascii')
            value = subprocess.run([shell, '-NoProfile', '-NonInteractive', '-EncodedCommand', encoded], **kwargs)
            if value.returncode:
                print('Owned fixture transaction stderr:', value.stderr.decode(errors='replace')[-4000:])
                # ACLs belong exclusively to this throwaway CI job. Retain the
                # before/after representation to diagnose scheduler normalization.
                for file in layout.root.glob('record-*.private.json'):
                    record=json.loads(file.read_text(encoding='utf-8'))
                    print('Owned fixture original ACL:', record.get('before',{}).get('security'))
                print('Owned fixture observed ACL:', io.snapshot()['rows'][0].get('security'))
            return value
        return subprocess.run(args, **kwargs)
    io = WindowsComponents(home, layout=layout, runner=runner)
    setup = ("$ErrorActionPreference='Stop';$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;"
        "$a=New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "+quote('-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "'+str(source)+'"')+';'
        "$t=New-ScheduledTaskTrigger -AtLogOn;$p=New-ScheduledTaskPrincipal -UserId $sid -LogonType Interactive -RunLevel Limited;"
        "$s=New-ScheduledTaskSettingsSet -Hidden -ExecutionTimeLimit ([TimeSpan]::Zero);"
        "Register-ScheduledTask -TaskName "+quote(marker)+" -Action $a -Trigger $t -Principal $p -Settings $s | Out-Null")
    installed = False
    try:
        command([shell, '-NoProfile', '-NonInteractive', '-Command', setup]); installed = True
        for running in (False, True):
            if running:
                command([shell, '-NoProfile', '-NonInteractive', '-Command', 'Start-ScheduledTask -TaskName '+quote(marker)])
                deadline = time.monotonic()+15
                while not io.snapshot()['rows'][0]['running']:
                    if time.monotonic() > deadline: raise AssertionError('Owned task did not start')
                    time.sleep(.3)
            else:
                command([shell, '-NoProfile', '-NonInteractive', '-Command', 'Disable-ScheduledTask -TaskName '+quote(marker)+'|Out-Null'])
            before = io.snapshot(); assert before['rows'][0]['owned'], before
            assert before['rows'][0]['running'] is running, before
            if not running: assert before['rows'][0]['enabled'] is False
            subject = ComponentMigration(StateStore(home/'state'), home, io=io)
            plan = subject.prepare(['guard']); assert plan['state'] == 'planned', plan
            assert subject.apply(plan['plan_id'], 'true')['state'] == 'confirmation_required'
            value = subject.apply(plan['plan_id'], True); assert value['state'] == 'completed', value
            assert io.snapshot()['rows'][0]['present'] is False
            # New object proves recovery uses OS-protected originals, not memory.
            subject = ComponentMigration(StateStore(home/'state'), home, io=WindowsComponents(home, layout=layout, runner=runner))
            plan = subject.prepare(restore=True); assert plan['state'] == 'planned', plan
            value = subject.apply(plan['plan_id'], True); assert value['state'] == 'restored', value
            after = io.snapshot()['rows'][0]; assert after['running'] is running and after['enabled'] is running, after
            if not running: command([shell, '-NoProfile', '-NonInteractive', '-Command', 'Enable-ScheduledTask -TaskName '+quote(marker)+'|Out-Null'])
        result['checks'] = ['actual COM read/stop/delete/create/readback', 'actor SID and DACL verified',
                            'strict boolean consent', 'disabled and stopped stay disabled', 'original running task resumes',
                            'recovery after new process object', 'account marker unchanged', 'no vendor script execution']
        assert preserve.read_bytes() == b'ACCOUNT_FIXTURE_ONLY'
        result['passed'] = True
    finally:
        if installed:
            cleanup = 'Stop-ScheduledTask -TaskName '+quote(marker)+' -ErrorAction SilentlyContinue;Unregister-ScheduledTask -TaskName '+quote(marker)+' -Confirm:$false -ErrorAction Stop'
            command([shell, '-NoProfile', '-NonInteractive', '-Command', cleanup])
            assert io.snapshot()['rows'][0]['present'] is False
        result['jobs_removed'] = True


def mac(home, result):
    from envscope.components_macos import MacComponents
    from scripts.build_timezone_worker import build
    marker = uuid.uuid4().hex; system_root = Path('/Library/PrivilegedHelperTools')/('envscope-components-fixture-'+marker)
    assert system_root.parent == Path('/Library/PrivilegedHelperTools') and system_root.name.startswith('envscope-components-fixture-')
    labels = {k: 'io.qudadd.envscope.fixture.'+k.replace('.', '-')+'.'+marker for k in ('guard', 'timezone', 'update.system', 'update.user')}
    layout = Layout(home, 'Darwin', fixture={'root': system_root/'receipt', 'task': 'unused',
        'labels': labels, 'daemons': system_root/'daemons', 'scripts': system_root/'scripts'})
    home.mkdir(parents=True, exist_ok=True)
    (home/'Library/LaunchAgents').mkdir(parents=True); (home/'.local/bin').mkdir(parents=True)
    user_source = home/'.local/bin/claude-switch.sh'; user_source.write_text('#!/bin/bash\nexit 0\n'); user_source.chmod(0o700)
    header = home/'fixture.h'
    values = {'ENVSCOPE_COMPONENT_ROOT': str(layout.root), 'ENVSCOPE_COMPONENT_SOURCE': str(layout.scripts),
        'ENVSCOPE_COMPONENT_DAEMONS': str(layout.daemons), 'ENVSCOPE_COMPONENT_HOME': str(home),
        'ENVSCOPE_COMPONENT_LABEL_GUARD': labels['guard'], 'ENVSCOPE_COMPONENT_LABEL_TIMEZONE': labels['timezone'],
        'ENVSCOPE_COMPONENT_LABEL_UPDATE': labels['update.system'], 'ENVSCOPE_COMPONENT_LABEL_USER': labels['update.user']}
    header.write_text('\n'.join('#define '+k+' '+json.dumps(v) for k,v in values.items())+'\n#define ENVSCOPE_COMPONENT_FIXTURE 1\n')
    compiled = build(destination=home/'compiled', fixture_header=header, component='components')
    binary = compiled/'components-helper'; metadata = json.loads((compiled/'components-helper.json').read_text())
    worker = {'path': str(binary), 'sha256': metadata['sha256']}
    import shlex
    source = home/'root-fixture.sh'; source.write_text('#!/bin/bash\nwhile true; do /bin/sleep 1; done\n'); source.chmod(0o700)
    setup = 'if [ ! -d /Library/PrivilegedHelperTools ]; then /bin/mkdir /Library/PrivilegedHelperTools; /bin/chmod 755 /Library/PrivilegedHelperTools; fi; '
    setup += '/bin/mkdir '+shlex.quote(str(system_root))+'; /bin/chmod 755 '+shlex.quote(str(system_root))+'; '
    setup += '/bin/mkdir '+shlex.quote(str(layout.daemons))+' '+shlex.quote(str(layout.scripts))+'; '
    for name in ('claude-bodyguard.sh', 'tz-watchdog.sh', 'claude-switch.sh'):
        setup += '/bin/cp '+shlex.quote(str(source))+' '+shlex.quote(str(layout.scripts/name))+'; /usr/sbin/chown 0:0 '+shlex.quote(str(layout.scripts/name))+'; /bin/chmod 755 '+shlex.quote(str(layout.scripts/name))+'; '
    definitions = {}
    for role in labels:
        value = {'Label': labels[role], 'ProgramArguments': ['/bin/bash', str(layout.script(role))]+(['update', '--auto'] if role.startswith('update.') else []),
                 'RunAtLoad': role == 'guard', 'StartInterval': 43200 if role.startswith('update.') else 10 if role == 'guard' else 3600}
        if role == 'update.system': value['Disabled'] = True
        definitions[role] = plistlib.dumps(value)
        if role == 'update.user': layout.definition(role).write_bytes(definitions[role])
        else:
            stage = home/(role+'.plist'); stage.write_bytes(definitions[role])
            setup += '/bin/cp '+shlex.quote(str(stage))+' '+shlex.quote(str(layout.definition(role)))+'; /usr/sbin/chown 0:0 '+shlex.quote(str(layout.definition(role)))+'; /bin/chmod 644 '+shlex.quote(str(layout.definition(role)))+'; '
    created = False; user_loaded = False
    try:
        created = True
        command(['/usr/bin/sudo', '-n', '/bin/sh', '-c', 'set -eu;'+setup])
        command(['/usr/bin/sudo', '-n', '/bin/launchctl', 'bootstrap', 'system', str(layout.definition('guard'))])
        command(['/bin/launchctl', 'bootstrap', 'gui/'+str(os.getuid()), str(layout.definition('update.user'))]); user_loaded = True
        def runner(args, **kwargs):
            if args[0] == '/usr/bin/osascript':
                text = args[-1]; code = json.loads(text[len('do shell script '):text.index(' with administrator privileges')])
                return subprocess.run(['/usr/bin/sudo', '-n', '/bin/sh', '-c', code], **kwargs)
            return subprocess.run(args, **kwargs)
        io = MacComponents(home, layout=layout, runner=runner, helper=lambda: worker)
        before = io.snapshot(); assert all(r['owned'] for r in before['rows']), before
        subject = ComponentMigration(StateStore(home/'state'), home, io=io)
        plan = subject.prepare(); assert plan['state'] == 'planned', plan
        value = subject.apply(plan['plan_id'], True); assert value['state'] == 'completed', value
        assert all(r['present'] is False and r['registered'] is False for r in io.snapshot()['rows'])
        subject = ComponentMigration(StateStore(home/'state'), home, io=MacComponents(home, layout=layout, runner=runner, helper=lambda: worker))
        plan = subject.prepare(restore=True); assert plan['state'] == 'planned', plan
        value = subject.apply(plan['plan_id'], True); assert value['state'] == 'restored', value
        after = io.snapshot(); rows = {r['id']: r for r in after['rows']}
        assert rows['guard']['registered'] and rows['update.user']['registered']
        assert not rows['timezone']['registered'] and not rows['update.system']['registered'] and not rows['update.system']['enabled']
        for role in labels: assert layout.definition(role).read_bytes() == definitions[role]
        result['checks'] = ['actual structured launchd identity', 'root guard bootout/bootstrap', 'user agent with privilege drop',
            'paused/unloaded and disabled remain paused', 'exact definition bytes and mode restored', 'protected native journal', 'restart recovery', 'no scripts or profiles removed']
        result['passed'] = True
    finally:
        if user_loaded: subprocess.run(['/bin/launchctl', 'bootout', 'gui/'+str(os.getuid())+'/'+labels['update.user']], capture_output=True, timeout=15)
        if created:
            for role in ('guard', 'timezone', 'update.system'):
                subprocess.run(['/usr/bin/sudo', '-n', '/bin/launchctl', 'bootout', 'system/'+labels[role]], capture_output=True, timeout=15)
            assert str(system_root).startswith('/Library/PrivilegedHelperTools/envscope-components-fixture-') and len(marker) == 32
            command(['/usr/bin/sudo', '-n', '/bin/rm', '-rf', str(system_root)])
            assert not system_root.exists()
        for role in labels:
            target = ('gui/'+str(os.getuid()) if role == 'update.user' else 'system')+'/'+labels[role]
            probe = subprocess.run(['/bin/launchctl', 'print', target], capture_output=True, timeout=6)
            assert probe.returncode and b'could not find service' in (probe.stdout+probe.stderr).lower(), target
        result['jobs_removed'] = True


def main():
    if os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('ENVSCOPE_COMPONENTS_ACCEPTANCE') != '1':
        raise SystemExit('Owned OS job acceptance is restricted to explicitly enabled CI')
    out = Path('artifacts/components-acceptance'); out.mkdir(parents=True, exist_ok=True)
    result = {'platform': platform.system(), 'passed': False, 'jobs_removed': False,
              'real_network_changed': False, 'real_accounts_used': False, 'vendor_executed': False}
    try:
        with tempfile.TemporaryDirectory(prefix='envscope-components-fixture-') as folder:
            home = Path(folder).resolve()
            (windows if platform.system() == 'Windows' else mac)(home, result)
    finally: (out/'result.json').write_text(json.dumps(result, indent=2)+'\n', encoding='utf-8')
    assert result['passed'] and result['jobs_removed'], result
    print(json.dumps(result))


if __name__ == '__main__': main()

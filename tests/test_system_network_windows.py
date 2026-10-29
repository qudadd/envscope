"""Inspect transport and parse scripts without changing Windows networking."""
import base64
import json
from pathlib import Path
import platform
import subprocess
import tempfile
import unittest
from unittest.mock import Mock

from envscope.system_network_windows import WindowsNetworkIO,script,powershell


class WindowsNetworkTests(unittest.TestCase):
    def test_elevated_body_is_immutable_encoded_stdin_not_a_writable_script_path(self):
        runner=Mock(return_value=Mock(returncode=0))
        io=WindowsNetworkIO(runner=runner,executable='C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe')
        io.execute('apply',{'format':1,'nonce':'a'*32,'owner':'S-1-5-21-1-2-3-1001','expected_record':'',
                            'adapters':[],'flush_dns':True})
        call=runner.call_args
        self.assertIn('ReadToEnd',call.args[0][-1])
        self.assertIn("WindowStyle='Hidden'",call.args[0][-1])
        self.assertIn("$options.Verb='RunAs'",call.args[0][-1])
        self.assertNotIn('-File',call.args[0][-1])
        source=base64.b64decode(call.kwargs['input']).decode('utf-16-le')
        self.assertIn('Get-FileHash -LiteralPath $inputPath',source)
        self.assertIn("record-",source)
        self.assertIn('System32/WindowsPowerShell/v1.0/Modules',source)
        self.assertIn('Set-NetAdapterBinding -Enabled $enabled',source)
        self.assertLess(len(call.kwargs['input']),31000)

    def test_snapshot_does_not_execute_the_privileged_transaction(self):
        body=script('snapshot')
        self.assertNotIn('$lease=[IO.File]::Open',body)
        self.assertNotIn("Publish $record 'prepared'",body)
        self.assertTrue(body.endswith('Read-Network | ConvertTo-Json -Depth 30 -Compress\n'))
        self.assertNotIn('Clear-DnsClientCache\n',body)

    def test_unrecognized_actions_and_fixture_partial_setup_are_rejected(self):
        with self.assertRaises(ValueError):script('run-anything')
        with self.assertRaises(ValueError):script('apply',data_file='x',data_sha='x'*64)
        with self.assertRaises(ValueError):script('snapshot',fixture_backend='function fake {}')

    def test_status_scope_and_shapes_are_validated(self):
        runner=Mock(return_value=Mock(returncode=0,stdout=json.dumps({'state':'not_configured','id':''}).encode()))
        io=WindowsNetworkIO(runner=runner,executable='fixture-not-executed')
        self.assertEqual(io.status()['state'],'not_configured')
        for value in ({'format':1,'state':'committed','id':'a'*32,'fixture':True},
                      {'format':True,'state':'committed','id':'a'*32,'fixture':False}):
            runner.return_value.stdout=json.dumps(value).encode()
            with self.assertRaises(ValueError):io.status()

    @unittest.skipUnless(platform.system()=='Windows','PowerShell 5 runtime regression')
    def test_receipt_replacement_and_event_append_use_only_owned_fixture_files(self):
        with tempfile.TemporaryDirectory(prefix='envscope-receipts-fixture-') as folder:
            # Exercise real .NET replacement/flush semantics without UAC, ACL
            # changes, network functions, or any path outside this test folder.
            body=script('status',fixture_backend='',fixture_root=Path(folder))
            body=body.removesuffix('Read-Record | ConvertTo-Json -Depth 30 -Compress\n')
            body+='\nfunction Protect($path,$directory,$public){}\nfunction Assert-Protected($path){}\n'
            body+="$r=@{id=('a'*32);format=1;fixture=$true;adapters=@()};Publish $r 'prepared';Publish $r 'committed'"
            result=subprocess.run([powershell(),'-NoProfile','-NonInteractive','-Command',body],
                                  capture_output=True,timeout=20)
            self.assertEqual(result.returncode,0,result.stderr.decode('utf-8',errors='replace'))
            receipt=json.loads((Path(folder)/'latest.json').read_text())
            self.assertEqual(receipt['state'],'committed')
            events=[json.loads(line) for p in Path(folder).glob('events-*.jsonl') for line in p.read_text().splitlines()]
            self.assertEqual([r['phase'] for r in events],['prepared','committed'])


if __name__=='__main__':unittest.main()

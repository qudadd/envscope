"""Only a unique owned named-pipe server; no installed core or network changes."""
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest.mock import Mock,patch
import uuid

from envscope.local_controller import LocalController,from_config
from envscope.windows_pipe import NamedPipeSocket,validate_pipe,validate_peer


class PipeValidationTests(unittest.TestCase):
    def test_only_literal_local_pipe_namespace_and_one_transport(self):
        value=r'\\.\pipe\verge-mihomo-S-1-5-21-123'
        self.assertEqual(validate_pipe(value),value)
        for invalid in (r'\\remote\pipe\core',r'\\?\pipe\core',r'\\.\pipe\nested\core','http://127.0.0.1',True,'',value+'\n'):
            with self.assertRaises(ValueError):validate_pipe(invalid)
        with self.assertRaises(ValueError):LocalController(origin='http://127.0.0.1:1',pipe=value)
        chosen=from_config({'external-controller-pipe':value,'external-controller':'127.0.0.1:1'},'Windows')
        self.assertEqual(chosen.pipe,value);self.assertIsNone(chosen.origin)

    def test_peer_requires_known_core_and_current_or_service_identity(self):
        own='S-1-5-21-1-2-3-1001'
        for sid in (own,'S-1-5-18','S-1-5-19','S-1-5-20'):
            validate_peer(r'C:\Programs\Mihomo\verge-mihomo.exe',sid,own)
        for image,sid in ((r'C:\other\python.exe',own),(r'C:\core\mihomo.exe','S-1-5-21-8-8-8-1001'),
                          ('mihomo.exe',own),(r'C:\core\mihomo.exe',None)):
            with self.assertRaises(ValueError):validate_peer(image,sid,own)

    def test_http_layer_auth_and_read_only_version_use_pipe_without_fallback(self):
        class Stream:
            def __init__(self):self.sent=[];self.closed=False
            def sendall(self,data):self.sent.append(data)
            def makefile(self,*args):return io.BytesIO(b'HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\n{"meta":true}')
            def close(self):self.closed=True
        stream=Stream()
        with patch('envscope.windows_pipe.NamedPipeSocket',return_value=stream),patch('envscope.local_controller.build_opener') as opener:
            controller=LocalController(pipe=r'\\.\pipe\fixture',secret='fixture-only-token')
            self.assertEqual(controller.request('/version'),{'meta':True})
            self.assertIn(b'Authorization: Bearer fixture-only-token',b''.join(stream.sent))
            self.assertTrue(stream.closed);opener.assert_not_called()
        with patch('envscope.windows_pipe.NamedPipeSocket',side_effect=ValueError('Peer unavailable')),patch('envscope.local_controller.build_opener') as opener:
            with self.assertRaises(ValueError):controller.request('/configs')
            opener.assert_not_called()
        with self.assertRaises(ValueError):controller.request('/version',{'enable':True})


@unittest.skipUnless(os.name=='nt','Actual Windows fixture IPC')
class WindowsPipeFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from envscope.system_network_windows import powershell,quote
        cls.folder=tempfile.TemporaryDirectory(prefix='envscope-pipe-fixture-');cls.root=Path(cls.folder.name).resolve()
        source=cls.root/'fixture.cs';cls.binary=cls.root/'verge-mihomo.exe'
        source.write_text(r'''using System;using System.IO;using System.IO.Pipes;using System.Text;using System.Threading;
class PipeFixture {
 static void Main(string[] args){
  for(int request=0;request<20;request++){
   using(var pipe=new NamedPipeServerStream(args[0],PipeDirection.InOut,1,PipeTransmissionMode.Byte,PipeOptions.Asynchronous)){
    File.WriteAllText(Path.Combine(args[1],"ready"),"ready");
    try{pipe.WaitForConnection();}catch(IOException){File.WriteAllText(Path.Combine(args[1],"request"),"");continue;}
    var bytes=new MemoryStream();int c;string text="";
    try{while(bytes.Length<65536 && (c=pipe.ReadByte())>=0){bytes.WriteByte((byte)c);text=Encoding.ASCII.GetString(bytes.ToArray());if(text.EndsWith("\r\n\r\n"))break;}}catch(IOException){}
    File.WriteAllText(Path.Combine(args[1],"request"),text);
    if(text.Length==0)continue;
    if(File.Exists(Path.Combine(args[1],"stall"))){Thread.Sleep(5000);continue;}
    string status=text.Contains("Authorization: Bearer fixture-only-token\r\n")?"200 OK":"401 Unauthorized";
    string body="{\"tun\":{\"enable\":true}}";
    byte[] response=Encoding.ASCII.GetBytes("HTTP/1.1 "+status+"\r\nContent-Type: application/json\r\nContent-Length: "+Encoding.ASCII.GetByteCount(body)+"\r\nConnection: close\r\n\r\n"+body);
    try{pipe.Write(response,0,response.Length);pipe.Flush();}catch(IOException){}
   }
  }
 }
}''')
        command=("$ErrorActionPreference='Stop';$env:PSModulePath=Join-Path ([Environment]::GetFolderPath('Windows')) 'System32/WindowsPowerShell/v1.0/Modules';"
                 "Add-Type -Path "+quote(source)+" -OutputAssembly "+quote(cls.binary)+" -OutputType ConsoleApplication")
        result=subprocess.run([powershell(),'-NoProfile','-NonInteractive','-Command',command],capture_output=True,timeout=30)
        if result.returncode:
            cls.folder.cleanup();raise RuntimeError(result.stderr.decode('utf-8',errors='replace')[-1200:])

    @classmethod
    def tearDownClass(cls):cls.folder.cleanup()

    def server(self,wrong_image=False,stall=False):
        directory=self.root/uuid.uuid4().hex;directory.mkdir()
        if stall:(directory/'stall').touch()
        name='envscope-fixture-'+uuid.uuid4().hex;binary=self.binary
        if wrong_image:
            binary=self.root/'unrecognized.exe';binary.write_bytes(self.binary.read_bytes())
        process=subprocess.Popen([str(binary),name,str(directory)],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        self.addCleanup(lambda:process.wait(timeout=5))
        self.addCleanup(lambda:process.terminate() if process.poll() is None else None)
        deadline=time.monotonic()+8
        while not (directory/'ready').exists():
            self.assertIsNone(process.poll())
            if time.monotonic()>deadline:self.fail('Owned pipe server was not ready')
            time.sleep(.05)
        return '\\\\.\\pipe\\'+name,directory

    def test_real_pipe_read_authentication_and_unknown_image_rejection(self):
        path,directory=self.server()
        controller=LocalController(pipe=path,secret='fixture-only-token')
        self.assertEqual(controller.request('/configs'),{'tun':{'enable':True}})
        with self.assertRaises(ValueError):LocalController(pipe=path,secret='wrong-fixture-token').request('/configs')
        other,folder=self.server(wrong_image=True)
        with self.assertRaises(ValueError):LocalController(pipe=other,secret='DO_NOT_SEND_FIXTURE').request('/configs')
        deadline=time.monotonic()+2
        while not (folder/'request').exists() and time.monotonic()<deadline:time.sleep(.02)
        self.assertEqual((folder/'request').read_text(),'')

    def test_silent_server_has_bounded_cancelled_io_and_resource_cleanup(self):
        path,_=self.server(stall=True);start=time.monotonic()
        pipe=NamedPipeSocket(path,timeout=.2)
        try:
            pipe.sendall(b'GET /configs HTTP/1.1\r\nHost: localhost\r\n\r\n')
            with self.assertRaises(TimeoutError):pipe.read(64)
        finally:pipe.close()
        self.assertLess(time.monotonic()-start,2)
        self.assertIsNone(pipe.handle)


if __name__=='__main__':unittest.main()

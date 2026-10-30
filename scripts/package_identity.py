"""Write native version resources and honest unsigned build identity."""
import json
import plistlib
from pathlib import Path

from envscope import __version__, __release__
from envscope.app_identity import APP_ID, build_identity


def windows_version_file(destination):
    from PyInstaller.utils.win32.versioninfo import VSVersionInfo, FixedFileInfo, StringFileInfo, StringTable, StringStruct, VarFileInfo, VarStruct
    parts=tuple(map(int,__version__.split('.')))+(int(__release__.rsplit('.',1)[-1]) if '-alpha.' in __release__ else 0,)
    value=VSVersionInfo(ffi=FixedFileInfo(filevers=parts,prodvers=parts,mask=0x3f,flags=0x2,OS=0x40004,fileType=1,subtype=0,date=(0,0)),
        kids=[StringFileInfo([StringTable('040904b0',[StringStruct(key,value) for key,value in {
            'CompanyName':'EnvScope contributors','FileDescription':'EnvScope desktop environment diagnostics',
            'FileVersion':__version__,'InternalName':APP_ID,'OriginalFilename':'EnvScope.exe',
            'ProductName':'EnvScope','ProductVersion':__release__,'LegalCopyright':'EnvScope contributors · MIT License'}.items()])]),
              VarFileInfo([VarStruct('Translation',[1033,1200])])])
    path=Path(destination);path.parent.mkdir(parents=True,exist_ok=True);path.write_text(str(value),encoding='utf-8')
    return path


def write_identity(app,system):
    app=Path(app)
    resources=app/'Contents/Resources' if system=='Darwin' else app
    resources.mkdir(parents=True,exist_ok=True)
    (resources/'build-identity.json').write_text(json.dumps(build_identity(system),indent=2),encoding='utf-8')
    if system=='Darwin':
        path=app/'Contents/Info.plist';value=plistlib.loads(path.read_bytes())
        value.update(CFBundleIdentifier=APP_ID,CFBundleShortVersionString=__version__,CFBundleVersion=__version__,
                     NSHumanReadableCopyright='EnvScope contributors · MIT License')
        path.write_bytes(plistlib.dumps(value))

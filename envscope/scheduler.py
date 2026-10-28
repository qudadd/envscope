"""Reviewed user-scoped schedules; no service is registered on construction.

Only the fixed EnvScope worker is scheduled. No browser/API field can supply an
executable, command, task name, principal, path or launchd label.
"""
from datetime import datetime, timedelta
import json
import os
from pathlib import Path
import platform
import plistlib
import re
import subprocess
import sys
import xml.etree.ElementTree as ET

from .remedies import _read, _replace, _safe

TASK = "EnvScopeMaintenance"
LABEL = "org.envscope.maintenance"
MARKER = "https://github.com/qudadd/envscope/maintenance-v1"
NS = "http://schemas.microsoft.com/windows/2004/02/mit/task"
INTERVALS = (5, 15, 60)


def runtime():
    if getattr(sys, "frozen", False):
        return [str(Path(sys.executable).resolve()), "--maintenance-worker"], str(Path(sys.executable).resolve().parent)
    return [str(Path(sys.executable).resolve()), "-m", "envscope.maintenance"], str(Path(__file__).resolve().parents[1])


def windows_xml(command, cwd, interval, sid, start=None):
    if type(interval) is not int or interval not in INTERVALS or not re.fullmatch(r"S-1-[0-9-]+", sid):
        raise ValueError("invalid user schedule")
    ET.register_namespace("", NS)
    task = ET.Element("{" + NS + "}Task", version="1.3")
    def node(parent, name, text=None, **attributes):
        item = ET.SubElement(parent, "{" + NS + "}" + name, attributes)
        if text is not None:
            item.text = str(text)
        return item
    info = node(task, "RegistrationInfo")
    node(info, "Description", MARKER)
    triggers = node(task, "Triggers")
    trigger = node(triggers, "TimeTrigger")
    node(trigger, "Enabled", "true")
    node(trigger, "StartBoundary", start or (datetime.now().astimezone() + timedelta(minutes=1)).isoformat(timespec="seconds"))
    repetition = node(trigger, "Repetition")
    node(repetition, "Interval", "PT" + str(interval) + "M")
    node(repetition, "StopAtDurationEnd", "false")
    login = node(triggers, "LogonTrigger")
    node(login, "Enabled", "true")
    node(login, "UserId", sid)
    principal = node(node(task, "Principals"), "Principal", id="CurrentUser")
    node(principal, "UserId", sid)
    node(principal, "LogonType", "InteractiveToken")
    node(principal, "RunLevel", "LeastPrivilege")
    settings = node(task, "Settings")
    for name, value in (("MultipleInstancesPolicy", "IgnoreNew"), ("DisallowStartIfOnBatteries", "false"),
                        ("StopIfGoingOnBatteries", "false"), ("StartWhenAvailable", "true"),
                        ("Enabled", "true"), ("Hidden", "true"), ("ExecutionTimeLimit", "PT3M")):
        node(settings, name, value)
    execute = node(node(task, "Actions", Context="CurrentUser"), "Exec")
    node(execute, "Command", command[0])
    node(execute, "Arguments", subprocess.list2cmdline(command[1:]))
    node(execute, "WorkingDirectory", cwd)
    # schtasks imports this through a Unicode XML reader: UTF-8 declarations
    # can fail with "unable to switch the encoding" despite passing the XSD.
    # Keep the declaration, BOM and actual file bytes consistently UTF-16.
    return ET.tostring(task, encoding="utf-16", xml_declaration=True)


def definition_text(body):
    """Read current UTF-16 Windows definitions and earlier UTF-8 definitions."""
    return body.decode("utf-16") if body.startswith((b"\xff\xfe", b"\xfe\xff")) else body.decode("utf-8")


def windows_identity(body):
    tree = ET.fromstring(body)
    actions = tree.find("{" + NS + "}Actions")
    principals = tree.find("{" + NS + "}Principals")
    triggers = tree.find("{" + NS + "}Triggers")
    if (actions is None or len(actions) != 1 or actions[0].tag != "{" + NS + "}Exec"
            or principals is None or len(principals) != 1 or triggers is None or len(triggers) != 2
            or {t.tag for t in triggers} != {"{" + NS + "}TimeTrigger", "{" + NS + "}LogonTrigger"}):
        return None
    def text(path, default=None):
        element = tree.find("/".join("{" + NS + "}" + p for p in path.split("/")))
        return default if element is None else element.text
    value = {k: text(p) for k, p in {
        "marker": "RegistrationInfo/Description", "program": "Actions/Exec/Command",
        "arguments": "Actions/Exec/Arguments", "cwd": "Actions/Exec/WorkingDirectory",
        "interval": "Triggers/TimeTrigger/Repetition/Interval", "sid": "Principals/Principal/UserId",
        "login_sid": "Triggers/LogonTrigger/UserId", "login_enabled": "Triggers/LogonTrigger/Enabled",
        "logon": "Principals/Principal/LogonType", "level": "Principals/Principal/RunLevel",
        "enabled": "Settings/Enabled"}.items()}
    # Export-ScheduledTask elides OS defaults. Absence is a documented value,
    # unlike an empty/invalid element or an unresolved account identity.
    for key, path in (("enabled", "Settings/Enabled"), ("login_enabled", "Triggers/LogonTrigger/Enabled"),
                      ("time_enabled", "Triggers/TimeTrigger/Enabled")):
        flag = text(path, "true")
        value[key] = {"1": "true", "0": "false"}.get(flag, flag)
    value["level"] = text("Principals/Principal/RunLevel", "LeastPrivilege")
    return value


def mac_plist(command, cwd, interval):
    if type(interval) is not int or interval not in INTERVALS:
        raise ValueError("invalid interval")
    return plistlib.dumps({"Label": LABEL, "ProgramArguments": command, "WorkingDirectory": cwd,
                          "StartInterval": interval * 60, "RunAtLoad": True, "ProcessType": "Background",
                          "EnvScopeOwner": MARKER}, sort_keys=True)


class UserScheduler:
    def __init__(self, home, root, system=None, runner=None, command=None, cwd=None, sid=None, uid=None):
        home_path = Path(os.path.abspath(home))
        self.home = home_path.resolve()
        root_path = Path(os.path.abspath(root))
        # Canonicalize only the trusted home alias (macOS /var -> /private/var,
        # or a relocated user home). Never resolve a link below the home root:
        # _safe must still reject linked/reparse maintenance children.
        self.root = self.home / root_path.relative_to(home_path) if root_path.is_relative_to(home_path) else root_path
        self.system = system or platform.system()
        self.runner = runner or subprocess.run
        actual_command, actual_cwd = runtime()
        self.command, self.cwd = command or actual_command, cwd or actual_cwd
        self.sid = sid
        self.uid = uid if uid is not None else (os.getuid() if hasattr(os, "getuid") else None)
        self.path = (self.home / "Library/LaunchAgents" / (LABEL + ".plist") if self.system == "Darwin"
                     else self.root / "task.xml")

    def _run(self, args):
        return self.runner(args, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=20,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))

    def _powershell(self, code):
        exe = str(Path(os.environ.get("WINDIR", "C:/Windows")) / "System32/WindowsPowerShell/v1.0/powershell.exe")
        return self._run([exe, "-NoProfile", "-NonInteractive", "-Command",
                          "[Console]::OutputEncoding=[Text.UTF8Encoding]::new();" + code])

    def build(self, interval):
        if self.system == "Windows":
            sid = self.sid
            if sid is None:
                result = self._powershell("[Security.Principal.WindowsIdentity]::GetCurrent().User.Value")
                if result.returncode:
                    raise ValueError("无法读取当前用户标识，未生成后台任务")
                sid = result.stdout.strip()
            body = windows_xml(self.command, self.cwd, interval, sid)
        elif self.system == "Darwin" and self.uid is not None:
            body = mac_plist(self.command, self.cwd, interval)
        else:
            raise ValueError("持续维护仅支持 Windows 和 macOS")
        return {"system": self.system, "body": definition_text(body), "command": self.command,
                "cwd": self.cwd, "interval": interval}

    def inspect(self, spec=None):
        try:
            if self.system == "Windows":
                code = ("try{$ErrorActionPreference='Stop';$t=@(Get-ScheduledTask -TaskPath '\\' -ErrorAction Stop|Where-Object {$_.TaskName -eq 'EnvScopeMaintenance'});"
                        "if($t.Count -eq 0){@{present=$false}|ConvertTo-Json -Compress}else{"
                        "$d=[xml](Export-ScheduledTask -TaskName 'EnvScopeMaintenance' -TaskPath '\\' -ErrorAction Stop);"
                        "$d.XmlResolver=$null;foreach($n in $d.SelectNodes('//*[local-name()=\"Principal\" or local-name()=\"LogonTrigger\"]/*[local-name()=\"UserId\"]')){"
                        "if($n.InnerText -notmatch '^S-1-[0-9-]+$'){$n.InnerText=[Security.Principal.NTAccount]::new($n.InnerText).Translate([Security.Principal.SecurityIdentifier]).Value}};"
                        "@{present=$true;xml=$d.OuterXml}|ConvertTo-Json -Compress}}catch{exit 2}")
                result = self._powershell(code)
                if result.returncode:
                    raise ValueError("task query failed")
                value = json.loads(result.stdout)
                present = value.get("present") is True
                actual = windows_identity(value["xml"]) if present else None
                expected = windows_identity(spec["body"]) if spec else None
                identity = lambda v: {k: x for k, x in v.items() if k not in ("enabled", "login_enabled", "time_enabled")} if v else None
                owned = bool(present and spec and actual and identity(actual) == identity(expected))
                registered = owned and all(actual[k] == "true" for k in ("enabled", "login_enabled", "time_enabled"))
            elif self.system == "Darwin":
                body = _read(self.path)
                present = body is not None
                owned = bool(present and spec and plistlib.loads(body) == plistlib.loads(spec["body"].encode("utf-8")))
                result = self._run(["/bin/launchctl", "print", f"gui/{self.uid}/{LABEL}"])
                loaded = result.returncode == 0
                present = present or loaded
                registered = owned and loaded
            else:
                return {"state": "unsupported", "present": False, "owned": False, "registered": False}
            return {"state": "registered" if registered else "conflict" if present and not owned else "missing",
                    "present": present, "owned": owned, "registered": registered}
        except (OSError, ValueError, TypeError, AttributeError, KeyError, ET.ParseError, subprocess.TimeoutExpired):
            return {"state": "unavailable", "present": None, "owned": False, "registered": False}

    def install(self, spec, previous=None):
        state = self.inspect(previous)
        if state["present"] is None or state["present"] and not state["owned"]:
            raise ValueError("同名任务不属于本方案或无法验证，未覆盖；请检查任务权限")
        before = _read(self.path)
        if before is not None and (previous is None or definition_text(before) != previous["body"]):
            raise ValueError("后台任务文件已被外部修改，未覆盖")
        _replace(self.path, spec["body"].encode("utf-16" if self.system == "Windows" else "utf-8"), before)
        try:
            if self.system == "Windows":
                args = [str(Path(os.environ.get("WINDIR", "C:/Windows")) / "System32/schtasks.exe"),
                        "/Create", "/TN", TASK, "/XML", str(self.path)]
                if state["present"]:
                    args.append("/F")
                result = self._run(args)
            else:
                if state["registered"]:
                    result = self._run(["/bin/launchctl", "bootout", f"gui/{self.uid}/{LABEL}"])
                    if result.returncode:
                        raise ValueError("旧的维护任务未能停用，未重复加载")
                result = self._run(["/bin/launchctl", "bootstrap", f"gui/{self.uid}", str(self.path)])
            if result.returncode or not self.inspect(spec)["registered"]:
                raise ValueError("操作系统没有确认维护任务已注册并启用")
        except (OSError, ValueError, subprocess.TimeoutExpired):
            # Preserve the reviewed definition for inspection/retry. The manager
            # has already disabled the worker before scheduling is attempted.
            raise ValueError("后台任务注册未确认；自动恢复保持停用，可检查权限后重试") from None
        return {"state": "registered"}

    def remove(self, spec):
        state = self.inspect(spec)
        if state["present"] is None or state["present"] and not state["owned"]:
            raise ValueError("后台任务归属无法确认；配置保持已停用，不删除同名任务")
        if state["present"] and (self.system == "Windows" or state["registered"]):
            args = ([str(Path(os.environ.get("WINDIR", "C:/Windows")) / "System32/schtasks.exe"), "/Delete", "/TN", TASK, "/F"]
                    if self.system == "Windows" else ["/bin/launchctl", "bootout", f"gui/{self.uid}/{LABEL}"])
            if self._run(args).returncode:
                raise ValueError("维护已停用，但操作系统任务移除尚未确认")
        body = _read(self.path)
        if body is not None:
            if spec is None or definition_text(body) != spec["body"]:
                raise ValueError("任务文件已经变化，保留供核对")
            _safe(self.path).unlink()
        return {"state": "removed"}

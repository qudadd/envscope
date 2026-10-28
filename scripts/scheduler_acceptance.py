"""Exercise actual user OS scheduling on disposable GitHub-hosted runners only.

The scheduled program is the production frozen maintenance entry point with
--check-runtime. It imports the worker and exits without probes, configuration
edits or a user's maintenance state. This checks OS registration, two automatic
runs, ownership and removal; it does not certify network or account usability.
"""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time

from envscope.scheduler import UserScheduler, LABEL, windows_identity, MARKER


def execution(scheduler):
    if scheduler.system == "Windows":
        result = scheduler._powershell(
            "$s=Get-ScheduledTaskInfo -TaskName 'EnvScopeMaintenance' -TaskPath '\\' -ErrorAction Stop;"
            "@{last_run=$s.LastRunTime.ToUniversalTime().ToString('o');result=[long]$s.LastTaskResult}|ConvertTo-Json -Compress")
        if result.returncode:
            raise RuntimeError("OS task execution record unavailable")
        value = json.loads(result.stdout)
        when = datetime.fromisoformat(value["last_run"].replace("Z", "+00:00"))
        return {"key": when.isoformat(), "at": when, "result": value["result"]}
    result = scheduler._run(["/bin/launchctl", "print", f"gui/{scheduler.uid}/{LABEL}"])
    if result.returncode:
        raise RuntimeError("launchd execution record unavailable")
    runs = re.search(r"^\s*runs\s*=\s*(\d+)\s*$", result.stdout, re.M)
    status = re.search(r"^\s*last exit code\s*=\s*(\d+)\s*$", result.stdout, re.M)
    return {"key": int(runs[1]) if runs else 0, "result": int(status[1]) if status else None}


def main(argv=None):
    # A local invocation must never register or remove the developer's real job.
    if os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("ENVSCOPE_SCHEDULER_ACCEPTANCE") != "1":
        print("Refused: real scheduler acceptance is restricted to opted-in disposable CI runners.")
        return 2
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1 or platform.system() not in ("Windows", "Darwin"):
        return 2
    executable = Path(args[0]).resolve(strict=True)
    expected_name = "EnvScope.exe" if platform.system() == "Windows" else "EnvScope"
    if executable.name != expected_name or not executable.is_file():
        raise ValueError("Expected the just-built native executable")
    command = [str(executable), "--maintenance-worker", "--check-runtime"]
    completed = subprocess.run(command, timeout=20, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    if completed.returncode:
        raise RuntimeError("Frozen worker self-check did not exit successfully")
    base = Path(tempfile.mkdtemp(prefix="envscope-scheduler-acceptance-")).resolve()
    home = base / "home with spaces 测试"
    home.mkdir()
    commands = []
    def runner(args, **kwargs):
        result = subprocess.run(args, **kwargs)
        if any(v in args for v in ("/Create", "/Delete", "bootstrap", "bootout")):
            # Only our attempted fixed registration/removal command; never log
            # arbitrary user task definitions or signed URLs/credentials.
            commands.append({"operation": next(v for v in args if v in ("/Create", "/Delete", "bootstrap", "bootout")),
                             "returncode": result.returncode, "stdout": result.stdout[:1200], "stderr": result.stderr[:1200]})
        return result
    scheduler = UserScheduler(home, home / ".envscope/maintenance", command=command, cwd=str(executable.parent), runner=runner)
    spec = scheduler.build(5)
    evidence = {"system": scheduler.system, "worker": "frozen-maintenance-check-runtime",
                "network_probes": False, "user_config_edits": False, "interval_minutes": 5,
                "registration": False, "automatic_runs": 0, "removed": False,
                "scope": "real OS scheduler lifecycle, not real Claude/network acceptance", "os_commands": commands}
    path = Path("artifacts/scheduler-acceptance.json")
    path.parent.mkdir(exist_ok=True)
    started = datetime.now(timezone.utc)
    attempted = False
    try:
        if scheduler.inspect()["present"] is not False:
            raise RuntimeError("A job already exists or ownership cannot be established; it was not changed")
        attempted = True
        scheduler.install(spec)
        if scheduler.inspect(spec).get("registered") is not True:
            raise RuntimeError("OS registration was not independently confirmed")
        evidence["registration"] = True
        print("OS registration confirmed; waiting for two automatic executions (no manual task trigger).", flush=True)
        seen = set()
        deadline = time.monotonic() + 480
        while time.monotonic() < deadline:
            value = execution(scheduler)
            if scheduler.system == "Windows":
                if value["at"] >= started and value["result"] == 0:
                    seen.add(value["key"])
                runs = len(seen)
            else:
                runs = value["key"] if value["result"] == 0 else 0
            if runs > evidence["automatic_runs"]:
                evidence["automatic_runs"] = runs
                print("Successful automatic worker executions: " + str(runs), flush=True)
                path.write_text(json.dumps(evidence, indent=2), encoding="utf-8")
            if runs >= 2:
                break
            time.sleep(5)
        if evidence["automatic_runs"] < 2:
            raise RuntimeError("Two successful automatic runs were not observed within eight minutes")
    except Exception as error:
        evidence["error"] = type(error).__name__ + ": " + str(error)
        if attempted and scheduler.system == "Windows":
            result = scheduler._powershell("Export-ScheduledTask -TaskName 'EnvScopeMaintenance' -TaskPath '\\' -ErrorAction SilentlyContinue")
            if result.returncode == 0 and result.stdout.strip():
                actual = windows_identity(result.stdout)
                if actual and actual.get("marker") == MARKER:
                    evidence["actual_identity"] = actual
                    evidence["expected_identity"] = windows_identity(spec["body"])
        raise
    finally:
        try:
            if attempted:
                state = scheduler.inspect(spec)
                if state.get("present") is False or state.get("owned") is True:
                    scheduler.remove(spec)
                    evidence["removed"] = scheduler.inspect(spec).get("present") is False
        finally:
            path.write_text(json.dumps(evidence, indent=2), encoding="utf-8")
            # Verify the absolute cleanup boundary before a recursive removal.
            if evidence["removed"] and base.parent == Path(tempfile.gettempdir()).resolve() and base.name.startswith("envscope-scheduler-acceptance-"):
                shutil.rmtree(base)
    if not evidence["removed"]:
        raise RuntimeError("OS job removal was not independently confirmed")
    print("Verified actual OS registration, repeated automatic execution and removal.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

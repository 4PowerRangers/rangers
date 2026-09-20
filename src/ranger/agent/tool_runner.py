from __future__ import annotations

import json
import os
import signal
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Mapping
from pathlib import Path
import time

MAX_PREVIEW = 2000
DEFAULT_TOOL_CANDIDATES = (
    "curl", "nmap", "sqlmap", "python3", "bash", "sh", "hashcat", "john",
)
ALLOWED_COMMAND_TOOLS = ("python3", "curl", "bash", "sh", "nmap")
AGENT_COMMAND_PATH_ENV = "RANGER_AGENT_COMMAND_PATH"
DEFAULT_AGENT_COMMAND_PATH = "/opt/ranger/agent-bin"


def agent_command_path() -> str:
    """Return the isolated command directory, without changing process PATH."""
    return os.environ.get(AGENT_COMMAND_PATH_ENV, DEFAULT_AGENT_COMMAND_PATH)


def resolve_executable(name: str, *, path: str | None = None) -> str | None:
    """Resolve an agent command only inside the agent execution directory."""
    return shutil.which(name, path=path or agent_command_path())


def available_tools(candidates: tuple[str, ...] = DEFAULT_TOOL_CANDIDATES) -> list[str]:
    """Return commands actually exposed by the agent execution directory."""
    return [name for name in candidates if resolve_executable(name)]


def materialize_profile(profile: Mapping[str, object], *, destination: str | Path | None = None) -> list[str]:
    """Expose only profile command_tools as links in the agent directory."""
    target = Path(destination or agent_command_path())
    target.mkdir(parents=True, exist_ok=True)
    for child in target.iterdir():
        if child.is_symlink() or child.is_file():
            child.unlink()
        elif child.is_dir():
            shutil.rmtree(child)
    tools = profile.get("command_tools", [])
    if not isinstance(tools, list) or any(not isinstance(item, str) for item in tools):
        raise ValueError("profile.command_tools must be a list of strings")
    invalid = [name for name in tools if name not in ALLOWED_COMMAND_TOOLS]
    if invalid:
        raise ValueError(f"unsupported command tools: {', '.join(invalid)}")
    tools = list(dict.fromkeys(tools))
    for name in tools:
        source = shutil.which(name)
        if not source:
            raise FileNotFoundError(f"profile command is not installed: {name}")
        (target / name).symlink_to(source)
    return available_tools(tuple(tools))


def _preview(value: bytes | str) -> str:
    text = value.decode("utf-8", "replace") if isinstance(value, bytes) else value
    for secret in (os.environ.get("DEEPSEEK_API_KEY", ""), os.environ.get("RANGER_DB_OBSERVER_TOKEN", "")):
        if secret:
            text = text.replace(secret, "[REDACTED]")
    return text[:MAX_PREVIEW]


def run(argv: list[str], timeout: float) -> dict[str, object]:
    if not argv or any(not isinstance(arg, str) for arg in argv):
        return {"status": "spawn_failed", "error": "argv must be non-empty strings"}
    executable = resolve_executable(argv[0])
    if not executable:
        return {"status": "spawn_failed", "error": "command unavailable in this variant", "executable": None}
    started = time.time()

    process = None
    try:
        with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
            process = subprocess.Popen(
                [executable, *argv[1:]], stdout=stdout_file, stderr=stderr_file,
                start_new_session=True,
                env={**os.environ, "PATH": agent_command_path()},
            )
            try:
                process.wait(timeout=timeout)
                status = "completed" if process.returncode == 0 else "failed"
            except subprocess.TimeoutExpired:
                try:
                    if os.name == "posix":
                        os.killpg(process.pid, signal.SIGKILL)
                    else:
                        process.kill()
                except (AttributeError, ProcessLookupError, PermissionError):
                    process.kill()
                process.wait()
                status = "timed_out"
            stdout_file.seek(0)
            stderr_file.seek(0)
            stdout = stdout_file.read(MAX_PREVIEW + 1)
            stderr = stderr_file.read(MAX_PREVIEW + 1)
            stdout_truncated = len(stdout) > MAX_PREVIEW
            stderr_truncated = len(stderr) > MAX_PREVIEW
    except (OSError, ValueError) as exc:
        return {"status": "spawn_failed", "error": type(exc).__name__, "executable": executable}
    return {
        "status": status, "pid": process.pid, "pid_namespace": "container",
        "executable": executable, "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(started)),
        "finished_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "exit_code": process.returncode, "stdout_preview": _preview(stdout),
        "stderr_preview": _preview(stderr), "stdout_truncated": stdout_truncated,
        "stderr_truncated": stderr_truncated,
    }


def main() -> None:
    if len(sys.argv) == 2 and sys.argv[1] == "--list":
        print(json.dumps(available_tools(), ensure_ascii=False))
        return
    if len(sys.argv) < 3 or sys.argv[1] != "--timeout":
        print(json.dumps({"status": "spawn_failed", "error": "usage"}))
        return
    try:
        timeout = float(sys.argv[2])
    except ValueError:
        print(json.dumps({"status": "spawn_failed", "error": "invalid timeout"}))
        return
    print(json.dumps(run(sys.argv[3:], timeout), ensure_ascii=False))


if __name__ == "__main__":
    main()
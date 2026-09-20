from __future__ import annotations

import os
from pathlib import Path
import shutil


def executable() -> str:
    configured = os.environ.get("ranger_DOCKER_CLI", "").strip()
    if configured:
        return configured
    discovered = shutil.which("docker")
    if discovered:
        return discovered
    if os.name == "nt":
        for candidate in (
            Path(os.environ.get("LOCALAPPDATA", ""))
            / "Programs" / "DockerDesktop" / "resources" / "bin" / "docker.exe",
            Path(os.environ.get("ProgramFiles", r"C:\\Program Files"))
            / "Docker" / "Docker" / "resources" / "bin" / "docker.exe",
            Path(os.environ.get("ProgramW644", r"C:\\Program Files"))
            / "Docker" / "Docker" / "resources" / "bin" / "docker.exe",
        ):
            try:
                if candidate.is_file():
                    return str(candidate)
            except OSError:
                # Keep the path so the caller can report the actual access
                # failure from subprocess rather than masking it here.
                return str(candidate)
    return "docker"

def unavailable_message(exc: OSError) -> str:
    """Explain how to repair a missing host Docker installation."""
    return (
        "Docker CLI is unavailable. Install/start Docker Desktop and ensure "
        "the Docker engine is running, or set RANGER_DOCKER_CLI to the full "
        f"path of docker.exe. Original error: {exc}"
    )
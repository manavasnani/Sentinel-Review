"""
Clean sample: subprocess used safely.

This file SHOULD produce ZERO findings. subprocess calls that use a list
argument and shell=False are explicitly safe — the OS does not interpret
shell metacharacters in the argument list.
"""

import subprocess
import shlex
from pathlib import Path


def list_directory(path: str) -> list[str]:
    """Safe: list args, shell=False (default), so no shell interpretation."""
    result = subprocess.run(
        ["ls", "-la", path],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.splitlines()


def ping_host(host: str) -> bool:
    """Safe: list arg means the host is passed as a single argv element."""
    result = subprocess.run(
        ["ping", "-c", "1", "-W", "2", host],
        capture_output=True,
    )
    return result.returncode == 0


def run_git_log(repo: Path) -> str:
    """Safe: explicit list, no shell, validated path."""
    if not repo.is_dir():
        raise ValueError(f"Not a directory: {repo}")
    result = subprocess.run(
        ["git", "-C", str(repo), "log", "--oneline", "-n", "10"],
        capture_output=True,
        text=True,
    )
    return result.stdout


def run_with_shlex_quote(user_input: str) -> str:
    """
    Safe: shlex.quote escapes shell metacharacters when shell=True is
    unavoidable. (List args remain preferable, but this is acceptable.)
    """
    quoted = shlex.quote(user_input)
    result = subprocess.run(
        f"echo {quoted}",
        shell=True,
        capture_output=True,
        text=True,
    )
    return result.stdout

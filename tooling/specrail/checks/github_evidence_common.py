"""Shared errors for read-only GitHub evidence adapters."""

import subprocess
from pathlib import Path
from typing import Any


class EvidenceError(ValueError):
    """Raised when GitHub evidence cannot be collected or normalized."""


def pack_path_prefix(repo: Path) -> str:
    """Return the pack root's location inside the enclosing git work tree.

    GitHub reports changed-file paths relative to the repository work tree
    root, while the pack resolves its own artifacts relative to the ``--repo``
    pack root. When a consumer nests the pack (Argus keeps it under
    ``tooling/specrail/``), the two coordinate systems differ by this prefix.
    Returns a ``"tooling/specrail/"``-style string, or ``""`` when the pack
    root is the work tree root or git metadata is unavailable.
    """
    try:
        completed = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "--show-toplevel"],
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError:
        return ""
    if completed.returncode != 0:
        return ""
    toplevel = Path(completed.stdout.strip())
    try:
        relative = Path(repo).resolve().relative_to(toplevel.resolve())
    except (OSError, ValueError):
        return ""
    if not relative.parts:
        return ""
    return relative.as_posix() + "/"


def json_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise EvidenceError(f"{label} must be a JSON object")
    return value


def json_array(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise EvidenceError(f"{label} must be a JSON array")
    return value

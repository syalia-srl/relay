"""The state file given to ``open``: JSON, mode 0600, replaced atomically."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

from .errors import RelayError

VERSION = 1


def load(path: Path) -> dict[str, Any] | None:
    """The state at ``path``, or None when this is the first run."""
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    except OSError as error:
        raise RelayError(f"cannot read the state file: {error}") from error
    try:
        # The state is a trusted local file, so this lenient parser is fine here; never use it on network input.
        value = json.loads(text)
    except ValueError as error:
        raise RelayError("the state file is not JSON") from error
    if not isinstance(value, dict) or value.get("v") != VERSION:
        raise RelayError("the state file has an unknown version")
    return value


def save(path: Path, value: dict[str, Any]) -> None:
    """Write ``value`` so a crash leaves either the old file or the new one.

    ``mkstemp`` creates the file at 0600, which is how PROTOCOL.md section 10.2
    keeps the static key unreadable to other users.
    """
    directory = path.parent
    try:
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        descriptor, name = tempfile.mkstemp(dir=directory, prefix=f".{path.name}.", suffix=".tmp")
    except OSError as error:
        raise RelayError(f"cannot write the state file: {error}") from error
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump({"v": VERSION, **value}, handle, separators=(",", ":"))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise

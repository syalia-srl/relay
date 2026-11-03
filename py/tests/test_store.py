"""L6: the state directory is private, like the file it holds."""

from __future__ import annotations

import stat
from pathlib import Path

from relay import store


def test_state_directory_is_0700(tmp_path: Path) -> None:
    path = tmp_path / "state" / "host"
    store.save(path, {"static": "00"})
    assert stat.S_IMODE((tmp_path / "state").stat().st_mode) == 0o700

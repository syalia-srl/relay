"""JSON parsing and field checks that PROTOCOL.md section 1 requires."""

from __future__ import annotations

import json
from typing import Any

MAX_INTEGER = 2**53 - 1
_B64URL = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
_HEX = set("0123456789abcdef")


def loads(text: str) -> Any:
    """Parse JSON, refusing a duplicate key anywhere in the object tree."""

    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result

    def constant(name: str) -> Any:
        raise ValueError(f"{name} is not JSON")

    return json.loads(text, object_pairs_hook=object_pairs, parse_constant=constant)


def is_integer(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= MAX_INTEGER


def is_hex64(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(char in _HEX for char in value)


def is_b64url(value: Any, length: int) -> bool:
    return isinstance(value, str) and len(value) == length and all(char in _B64URL for char in value)

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..stage_binary import StageAInputError


def read_json_object(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise StageAInputError(f"cannot read {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise StageAInputError(f"{path} must contain a JSON object")
    return payload


_read_json = read_json_object


def write_text_if_changed(path: Path, content: str) -> None:
    if path.exists() and path.read_text(encoding="utf-8") == content:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")

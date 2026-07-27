from __future__ import annotations

import hashlib
import json
import math
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


def utc_now() -> str:
    source_date_epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if source_date_epoch is not None:
        try:
            timestamp = int(source_date_epoch, 10)
        except ValueError as error:
            raise ValueError(
                "SOURCE_DATE_EPOCH must be an integer Unix timestamp"
            ) from error
        if timestamp < 0:
            raise ValueError("SOURCE_DATE_EPOCH must be non-negative")
        return datetime.fromtimestamp(timestamp, timezone.utc).isoformat()
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_text(data: str) -> str:
    return sha256_bytes(data.encode("utf-8"))


def json_dumps(data: Any) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for value in data:
        counts[value] += 1
    total = len(data)
    return -sum((count / total) * math.log2(count / total) for count in counts if count)


def unique_preserve_order(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


_POSIX_ABSOLUTE_PATH = re.compile(r"(?<![A-Za-z0-9_./-])/(?:[^\s,;`]+)")
_WINDOWS_ABSOLUTE_PATH = re.compile(r"(?<![A-Za-z0-9_])(?:[A-Za-z]:\\\\|[A-Za-z]:/)(?:[^\s,;`]+)")


def public_text(value: object) -> str:
    text = "" if value is None else str(value)
    text = _WINDOWS_ABSOLUTE_PATH.sub("[private path]", text)
    return _POSIX_ABSOLUTE_PATH.sub("[private path]", text)

"""Independent semantic-object replay parsing and identity primitives."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from ..artifacts.artifact_set import canonical_sha256_v3
from ..errors import ToolkitInputError
from ..util import json_dumps, sha256_bytes

def _fail(message: str) -> None:
    raise ToolkitInputError(f"semantic-object independent replay: {message}")


def _object(value: object, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        _fail(f"{context} is not an object")
    return value


def _array(value: object, context: str) -> list[Any]:
    if not isinstance(value, list):
        _fail(f"{context} is not an array")
    return value


def _canonical_bytes(value: object) -> bytes:
    return (json_dumps(value) + "\n").encode("utf-8")


def _selection_reference(selection: Mapping[str, Any] | None) -> object:
    if selection is None:
        return None
    return {
        "member": "qualified-platform-selection.json",
        "status": selection["status"],
        "identity": selection["selection_sha256"],
        "content_sha256": sha256_bytes(_canonical_bytes(selection)),
        "counts": dict(_object(selection["counts"], "selection counts")),
    }


def _load(path: Path, context: str) -> dict[str, Any]:
    try:
        data = Path(path).read_bytes()
        value = json.loads(data)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        _fail(f"cannot read {context}: {exc}")
    payload = dict(_object(value, context))
    if data != _canonical_bytes(payload):
        _fail(f"{context} is not canonical JSON")
    return payload


def _function_id(transfer_id: str) -> str:
    return f"original:function:{transfer_id}"


def _object_id(origin: str) -> str:
    return f"original:object:{origin}"


def _import_id(slot_id: str, delay: bool) -> str:
    return f"external:{'delay-import' if delay else 'import'}:{slot_id}"


def _runtime_id(provider: str) -> str:
    return f"platform:runtime-primitive:{provider}"


def _semantic_import_identity(call: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "dll": str(call["dll"]),
        "symbol": call["symbol"],
        "ordinal": call["ordinal"],
    }


def _semantic_import_id(identity: Mapping[str, Any]) -> str:
    return f"external:function-import:{canonical_sha256_v3(identity)[:24]}"


def _data_anchor_id(rva: int) -> str:
    return f"original:data-anchor:rva:{rva:08x}"


def _tls_anchor_id(role: str, rva: int) -> str:
    return f"original:tls:{role}:{rva:08x}"


def _load_config_anchor_id(role: str, name: str, rva: int) -> str:
    return f"original:load-config:{role}:{name}:{rva:08x}"


def _resource_anchor_id(role: str, relative_offset: int) -> str:
    return f"original:resource:{role}:{relative_offset:08x}"

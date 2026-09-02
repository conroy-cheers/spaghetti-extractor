"""Content identities shared by deterministic phase and receipt manifests."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from .build_formats import CA_PHASE_MANIFEST_FORMAT, CA_RECEIPT_GATE_FORMAT


def content_identity(path_value: Path | str) -> dict[str, Any]:
    path = Path(path_value)
    path_text = str(path)
    if not path_text.startswith("/nix/store/"):
        raise ValueError("every content-addressed input must be a Nix store path")
    if path.is_file():
        data = path.read_bytes()
        return {
            "kind": "file",
            "sha256": hashlib.sha256(data).hexdigest(),
            "size_bytes": len(data),
        }
    if not path.is_dir():
        raise ValueError(f"content-addressed input does not exist: {path_text}")
    digest = hashlib.sha256()
    file_count = 0
    size_bytes = 0
    for child in sorted(path.rglob("*")):
        relative = child.relative_to(path).as_posix().encode("utf-8")
        if child.is_symlink():
            kind = b"symlink"
            data = child.readlink().as_posix().encode("utf-8")
        elif child.is_file():
            kind = b"file"
            data = child.read_bytes()
            file_count += 1
            size_bytes += len(data)
        elif child.is_dir():
            kind = b"directory"
            data = b""
        else:
            raise ValueError(
                f"content-addressed input contains an unsupported node: {child}"
            )
        executable = b"1" if child.stat().st_mode & 0o111 else b"0"
        for field in (kind, relative, executable, data):
            digest.update(len(field).to_bytes(8, "big"))
            digest.update(field)
    return {
        "kind": "directory",
        "sha256": digest.hexdigest(),
        "file_count": file_count,
        "size_bytes": size_bytes,
    }


def _python_closure_identity(path: Path) -> dict[str, Any]:
    closure_bytes = path.read_bytes()
    closure = json.loads(closure_bytes)
    if (
        not isinstance(closure, Mapping)
        or closure.get("format")
        != "spaghetti-extractor-python-module-closure-v2"
        or not isinstance(closure.get("files"), list)
    ):
        raise ValueError("Python module closure manifest is malformed")
    return {
        "manifest_sha256": hashlib.sha256(closure_bytes).hexdigest(),
        "file_count": len(closure["files"]),
    }


def _input_identities(inputs: Mapping[str, Path]) -> list[dict[str, Any]]:
    if any(not name for name in inputs):
        raise ValueError("content-addressed input names must be nonempty")
    return [
        {"name": name, **content_identity(path)}
        for name, path in sorted(inputs.items())
    ]


def phase_manifest(
    *,
    phase: str,
    content_addressed: bool,
    artifact_name: str,
    artifact: Mapping[str, Any],
    artifact_bytes: bytes,
    inputs: Mapping[str, Path],
    python_closure_manifest: Path,
) -> dict[str, Any]:
    """Describe one deterministic JSON phase without granting authority."""

    return {
        "format": CA_PHASE_MANIFEST_FORMAT,
        "phase": phase,
        "content_addressed": content_addressed,
        "inputs": _input_identities(inputs),
        "python_module_closure": _python_closure_identity(
            python_closure_manifest
        ),
        "artifact": {
            "name": artifact_name,
            "format": artifact["format"],
            # Intent/source artifacts intentionally have no authority status.
            # The phase constructor supplies an explicit allowed-status set for
            # receipt-like artifacts, so absence here is unambiguous.
            "status": artifact.get("status"),
            "sha256": hashlib.sha256(artifact_bytes).hexdigest(),
        },
    }


def receipt_gate_manifest(
    *,
    gate: str,
    phase_role: str,
    artifact_name: str,
    artifact: Mapping[str, Any],
    artifact_bytes: bytes,
    inputs: Mapping[str, Path],
    python_closure_manifest: Path,
) -> dict[str, Any]:
    return {
        "format": CA_RECEIPT_GATE_FORMAT,
        "status": "complete",
        "gate": gate,
        "phase_role": phase_role,
        "acceptance_authority": "none",
        "inputs": _input_identities(inputs),
        "python_module_closure": _python_closure_identity(
            python_closure_manifest
        ),
        "artifact": {
            "name": artifact_name,
            "format": artifact["format"],
            "status": artifact["status"],
            "sha256": hashlib.sha256(artifact_bytes).hexdigest(),
        },
    }


__all__ = ["content_identity", "phase_manifest", "receipt_gate_manifest"]

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from ..stage_binary import StageAInputError
from ..util import sha256_file, write_json
from .model import _exact_fields, _identifier, _nonempty_string, _object, _relative_path, _sha256


OPAQUE_STAGE_B_BUNDLE_FORMAT = "stage-b-opaque-input-bundle-v1"
_ALLOWED_STAGE_A_ROLES = frozenset({
    "reference_contract",
    "coverage_gaps",
    "abi_callsites",
    "block_contracts",
    "repair_units",
    "semantic_transfer_contracts",
    "state_machine",
    "proof_obligation_inventory",
})
_PROHIBITED_ROLES = frozenset({
    "original_pe",
    "generator_semantic_program",
    "generator_seed",
    "ground_truth_map",
    "transformation_history",
    "private_lowering_metadata",
    "original_runtime_trace",
})


@dataclass(frozen=True)
class OpaqueStageBInput:
    id: str
    role: str
    origin: str
    path: str
    sha256: str
    bytes: int

    @classmethod
    def parse(cls, payload: Mapping[str, Any], *, context: str) -> "OpaqueStageBInput":
        _exact_fields(payload, {"id", "role", "origin", "path", "sha256", "bytes"}, context)
        origin = payload["origin"]
        if origin not in {"stage_a_static_export", "manual_annotation"}:
            raise StageAInputError(f"{context}.origin is unsupported")
        role = _identifier(payload["role"], f"{context}.role")
        if role in _PROHIBITED_ROLES:
            raise StageAInputError(f"{context}.role is prohibited at the opaque Stage B boundary")
        if origin == "stage_a_static_export" and role not in _ALLOWED_STAGE_A_ROLES:
            raise StageAInputError(f"{context}.role is not an allowed Stage A static export")
        if origin == "manual_annotation" and not role.startswith("manual-"):
            raise StageAInputError(f"{context}.role must identify a manual annotation")
        size = payload["bytes"]
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise StageAInputError(f"{context}.bytes must be a nonnegative integer")
        return cls(
            id=_identifier(payload["id"], f"{context}.id"),
            role=role,
            origin=str(origin),
            path=_relative_path(payload["path"], f"{context}.path"),
            sha256=_sha256(payload["sha256"], f"{context}.sha256"),
            bytes=size,
        )

    def to_payload(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "role": self.role,
            "origin": self.origin,
            "path": self.path,
            "sha256": self.sha256,
            "bytes": self.bytes,
        }


def build_opaque_stage_b_input_bundle(
    *,
    out: Path,
    stage_a_artifacts: Sequence[tuple[str, Path]],
    manual_annotations: Sequence[tuple[str, Path]] = (),
) -> dict[str, Any]:
    out = Path(out).resolve()
    if out.exists():
        shutil.rmtree(out)
    inputs_dir = out / "inputs"
    inputs_dir.mkdir(parents=True)
    rows: list[OpaqueStageBInput] = []
    seen_roles: set[str] = set()
    combined = [
        ("stage_a_static_export", role, Path(path))
        for role, path in stage_a_artifacts
    ] + [
        ("manual_annotation", f"manual-{role}", Path(path))
        for role, path in manual_annotations
    ]
    for index, (origin, role, source) in enumerate(combined):
        if role in seen_roles:
            raise StageAInputError(f"opaque Stage B input role is duplicated: {role}")
        seen_roles.add(role)
        if not source.is_file() or source.is_symlink():
            raise StageAInputError(
                f"opaque Stage B input must be a regular non-symlink file: {source}"
            )
        suffix = "".join(source.suffixes)[-32:]
        destination = inputs_dir / f"{index:03d}-{role}{suffix}"
        shutil.copyfile(source, destination)
        row = OpaqueStageBInput.parse({
            "id": f"input-{index:03d}",
            "role": role,
            "origin": origin,
            "path": destination.relative_to(out).as_posix(),
            "sha256": sha256_file(destination),
            "bytes": destination.stat().st_size,
        }, context=f"opaque Stage B input {index}")
        rows.append(row)
    if "reference_contract" not in seen_roles or "state_machine" not in seen_roles:
        raise StageAInputError(
            "opaque Stage B bundle requires reference_contract and state_machine exports"
        )
    payload = {
        "format": OPAQUE_STAGE_B_BUNDLE_FORMAT,
        "status": "isolated",
        "inputs": [row.to_payload() for row in rows],
        "policy": {
            "original_pe_present": False,
            "original_runtime_trace_present": False,
            "generator_semantics_present": False,
            "ground_truth_map_present": False,
            "undeclared_inputs_allowed": False,
        },
    }
    write_json(out / "manifest.json", payload)
    validate_opaque_stage_b_input_bundle(out / "manifest.json")
    return payload


def validate_opaque_stage_b_input_bundle(manifest_path: Path) -> dict[str, Any]:
    manifest_path = Path(manifest_path).resolve()
    root = manifest_path.parent
    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise StageAInputError(f"cannot read opaque Stage B bundle: {exc}") from exc
    manifest = _object(payload, "opaque Stage B bundle")
    _exact_fields(manifest, {"format", "status", "inputs", "policy"}, "opaque Stage B bundle")
    if manifest["format"] != OPAQUE_STAGE_B_BUNDLE_FORMAT or manifest["status"] != "isolated":
        raise StageAInputError("unsupported or unisolated Stage B input bundle")
    raw_inputs = manifest["inputs"]
    if not isinstance(raw_inputs, list):
        raise StageAInputError("opaque Stage B inputs must be a list")
    inputs = tuple(
        OpaqueStageBInput.parse(
            _object(item, f"opaque Stage B input {index}"),
            context=f"opaque Stage B input {index}",
        )
        for index, item in enumerate(raw_inputs)
    )
    if len({item.id for item in inputs}) != len(inputs) or len({item.role for item in inputs}) != len(inputs):
        raise StageAInputError("opaque Stage B input ids and roles must be unique")
    policy = _object(manifest["policy"], "opaque Stage B policy")
    _exact_fields(policy, {
        "original_pe_present", "original_runtime_trace_present",
        "generator_semantics_present", "ground_truth_map_present",
        "undeclared_inputs_allowed",
    }, "opaque Stage B policy")
    if any(value is not False for value in policy.values()):
        raise StageAInputError("opaque Stage B policy admits a prohibited input class")
    for item in inputs:
        path = (root / item.path).resolve()
        if root not in path.parents or not path.is_file() or path.is_symlink():
            raise StageAInputError(f"opaque Stage B input {item.id} is not contained")
        if path.stat().st_size != item.bytes or sha256_file(path) != item.sha256:
            raise StageAInputError(f"opaque Stage B input {item.id} binding changed")
    observed_files = {
        path.resolve()
        for path in root.rglob("*")
        if path.is_file() and path.resolve() != manifest_path
    }
    declared_files = {(root / item.path).resolve() for item in inputs}
    if observed_files != declared_files:
        raise StageAInputError("opaque Stage B bundle contains undeclared files")
    roles = {item.role for item in inputs}
    if not {"reference_contract", "state_machine"}.issubset(roles):
        raise StageAInputError("opaque Stage B bundle omits required static exports")
    return {
        "format": "stage-b-opaque-input-bundle-audit-v1",
        "status": "pass",
        "manifest_sha256": sha256_file(manifest_path),
        "inputs": len(inputs),
        "roles": sorted(roles),
        "prohibited_inputs": [],
    }

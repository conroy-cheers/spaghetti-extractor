from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from ..stage_b_api_catalog import load_machine_call_catalog
from ..stage_b_state_machine import (
    load_stage_a_reference_contract_binding,
    validate_stage_b_state_machine_export_chain,
)
from ..stage_binary import StageAInputError
from ..util import sha256_file, write_json
from .model import _exact_fields, _identifier, _object, _relative_path, _sha256


OPAQUE_STAGE_B_BUNDLE_FORMAT = "stage-b-opaque-input-bundle-v2"
OPAQUE_STAGE_B_CHAIN_FORMAT = "stage-b-opaque-provenance-chain-v1"
OPAQUE_STAGE_B_AUDIT_FORMAT = "stage-b-opaque-input-bundle-audit-v2"

_REQUIRED_STAGE_A_ROLES = frozenset({
    "reference_contract",
    "semantic_transfer_contracts",
    "state_machine",
})
_PROHIBITED_ROLES = frozenset({
    "original_pe",
    "generator_semantic_program",
    "generator_seed",
    "ground_truth",
    "ground_truth_map",
    "source_labels",
    "transformation_history",
    "private_lowering_metadata",
    "original_runtime_trace",
})
_PROHIBITED_FIELDS = _PROHIBITED_ROLES | frozenset({"original_source"})
_STAGE_A_PROOF_ONLY_MANUAL_ROLES = frozenset({
    "manual-relational-proof-contract",
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
        if origin == "stage_a_static_export" and role not in _REQUIRED_STAGE_A_ROLES:
            raise StageAInputError(
                f"{context}.role is not a typed Stage A export accepted by this boundary"
            )
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


@dataclass(frozen=True)
class OpaqueStageBProvenanceChain:
    original_pe_sha256: str
    reference_contract_sha256: str
    semantic_transfer_contracts_sha256: str
    state_machine_sha256: str
    transfer_count: int

    @classmethod
    def parse(
        cls, payload: Mapping[str, Any], *, context: str
    ) -> "OpaqueStageBProvenanceChain":
        _exact_fields(payload, {
            "format",
            "original_pe_sha256",
            "reference_contract_sha256",
            "semantic_transfer_contracts_sha256",
            "state_machine_sha256",
            "transfer_count",
            "derivation",
        }, context)
        if payload["format"] != OPAQUE_STAGE_B_CHAIN_FORMAT:
            raise StageAInputError(f"{context}.format is unsupported")
        if payload["derivation"] != (
            "original-pe -> stage-a-reference-contract -> "
            "stage-a-semantic-transfer-contracts -> stage-b-state-machine"
        ):
            raise StageAInputError(f"{context}.derivation is unsupported")
        count = payload["transfer_count"]
        if isinstance(count, bool) or not isinstance(count, int) or count <= 0:
            raise StageAInputError(f"{context}.transfer_count must be positive")
        return cls(
            original_pe_sha256=_sha256(
                payload["original_pe_sha256"], f"{context}.original_pe_sha256"
            ),
            reference_contract_sha256=_sha256(
                payload["reference_contract_sha256"],
                f"{context}.reference_contract_sha256",
            ),
            semantic_transfer_contracts_sha256=_sha256(
                payload["semantic_transfer_contracts_sha256"],
                f"{context}.semantic_transfer_contracts_sha256",
            ),
            state_machine_sha256=_sha256(
                payload["state_machine_sha256"], f"{context}.state_machine_sha256"
            ),
            transfer_count=count,
        )

    def to_payload(self) -> dict[str, Any]:
        return {
            "format": OPAQUE_STAGE_B_CHAIN_FORMAT,
            "original_pe_sha256": self.original_pe_sha256,
            "reference_contract_sha256": self.reference_contract_sha256,
            "semantic_transfer_contracts_sha256": self.semantic_transfer_contracts_sha256,
            "state_machine_sha256": self.state_machine_sha256,
            "transfer_count": self.transfer_count,
            "derivation": (
                "original-pe -> stage-a-reference-contract -> "
                "stage-a-semantic-transfer-contracts -> stage-b-state-machine"
            ),
        }


def build_opaque_stage_b_input_bundle(
    *,
    out: Path,
    original_pe: Path,
    reference_contract: Path,
    semantic_transfer_contracts: Path,
    state_machine: Path,
    manual_annotations: Sequence[tuple[str, Path]] = (),
) -> dict[str, Any]:
    """Build the opaque handoff after validating the complete static hash chain."""

    original_pe = Path(original_pe).resolve()
    reference_contract = Path(reference_contract).resolve()
    semantic_transfer_contracts = Path(semantic_transfer_contracts).resolve()
    state_machine = Path(state_machine).resolve()
    reference = load_stage_a_reference_contract_binding(
        reference_contract, original_pe=original_pe
    )
    state_binding = validate_stage_b_state_machine_export_chain(
        state_machine=state_machine,
        reference_contract=reference_contract,
        semantic_transfer_contracts=semantic_transfer_contracts,
        original_pe=original_pe,
    )
    chain = OpaqueStageBProvenanceChain(
        original_pe_sha256=reference.original_pe_sha256,
        reference_contract_sha256=reference.sha256,
        semantic_transfer_contracts_sha256=state_binding.semantic_transfer_contracts_sha256,
        state_machine_sha256=state_binding.sha256,
        transfer_count=state_binding.transfer_count,
    )

    out = Path(out).resolve()
    if out.exists():
        shutil.rmtree(out)
    inputs_dir = out / "inputs"
    inputs_dir.mkdir(parents=True)
    rows: list[OpaqueStageBInput] = []
    seen_roles: set[str] = set()
    combined = [
        ("stage_a_static_export", "reference_contract", reference_contract),
        ("stage_a_static_export", "semantic_transfer_contracts", semantic_transfer_contracts),
        ("stage_a_static_export", "state_machine", state_machine),
    ] + [
        ("manual_annotation", f"manual-{role}", Path(path).resolve())
        for role, path in manual_annotations
    ]
    for index, (origin, role, source) in enumerate(combined):
        if role in seen_roles:
            raise StageAInputError(f"opaque Stage B input role is duplicated: {role}")
        seen_roles.add(role)
        _validate_source_input(source, role=role, origin=origin)
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
    payload = {
        "format": OPAQUE_STAGE_B_BUNDLE_FORMAT,
        "status": "isolated",
        "inputs": [row.to_payload() for row in rows],
        "provenance_chain": chain.to_payload(),
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
    _exact_fields(
        manifest,
        {"format", "status", "inputs", "provenance_chain", "policy"},
        "opaque Stage B bundle",
    )
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
    stage_a_roles = {item.role for item in inputs if item.origin == "stage_a_static_export"}
    if stage_a_roles != _REQUIRED_STAGE_A_ROLES:
        raise StageAInputError("opaque Stage B bundle has an incomplete or untyped Stage A export set")

    policy = _object(manifest["policy"], "opaque Stage B policy")
    _exact_fields(policy, {
        "original_pe_present", "original_runtime_trace_present",
        "generator_semantics_present", "ground_truth_map_present",
        "undeclared_inputs_allowed",
    }, "opaque Stage B policy")
    if any(value is not False for value in policy.values()):
        raise StageAInputError("opaque Stage B policy admits a prohibited input class")
    paths_by_role: dict[str, Path] = {}
    for item in inputs:
        path = (root / item.path).resolve()
        if root not in path.parents or not path.is_file() or path.is_symlink():
            raise StageAInputError(f"opaque Stage B input {item.id} is not contained")
        if path.stat().st_size != item.bytes or sha256_file(path) != item.sha256:
            raise StageAInputError(f"opaque Stage B input {item.id} binding changed")
        _validate_source_input(path, role=item.role, origin=item.origin)
        paths_by_role[item.role] = path
    observed_files = {
        path.resolve()
        for path in root.rglob("*")
        if path.is_file() and path.resolve() != manifest_path
    }
    declared_files = {(root / item.path).resolve() for item in inputs}
    if observed_files != declared_files:
        raise StageAInputError("opaque Stage B bundle contains undeclared files")

    chain = OpaqueStageBProvenanceChain.parse(
        _object(manifest["provenance_chain"], "opaque Stage B provenance chain"),
        context="opaque Stage B provenance chain",
    )
    reference = load_stage_a_reference_contract_binding(paths_by_role["reference_contract"])
    state_binding = validate_stage_b_state_machine_export_chain(
        state_machine=paths_by_role["state_machine"],
        reference_contract=paths_by_role["reference_contract"],
        semantic_transfer_contracts=paths_by_role["semantic_transfer_contracts"],
    )
    expected_chain = OpaqueStageBProvenanceChain(
        original_pe_sha256=reference.original_pe_sha256,
        reference_contract_sha256=reference.sha256,
        semantic_transfer_contracts_sha256=state_binding.semantic_transfer_contracts_sha256,
        state_machine_sha256=state_binding.sha256,
        transfer_count=state_binding.transfer_count,
    )
    if chain != expected_chain:
        raise StageAInputError("opaque Stage B provenance chain does not match its typed exports")
    return {
        "format": OPAQUE_STAGE_B_AUDIT_FORMAT,
        "status": "pass",
        "manifest_sha256": sha256_file(manifest_path),
        "inputs": len(inputs),
        "roles": sorted(item.role for item in inputs),
        "provenance_chain": chain.to_payload(),
        "prohibited_inputs": [],
    }


def _validate_source_input(path: Path, *, role: str, origin: str) -> None:
    if not path.is_file() or path.is_symlink():
        raise StageAInputError(f"opaque Stage B input must be a regular non-symlink file: {path}")
    if origin == "stage_a_static_export":
        _reject_private_structured_file(path, context=f"Stage A export {role}")
        return
    if role == "manual-machine-call-catalog":
        try:
            load_machine_call_catalog(path)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            raise StageAInputError(f"manual machine-call catalog is invalid: {exc}") from exc
        return
    if role == "manual-relational-proof-contract":
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise StageAInputError(
                f"manual relational proof contract is invalid JSON: {exc}"
            ) from exc
        contract = _object(payload, "manual relational proof contract")
        _reject_private_fields(
            contract, context="manual relational proof contract"
        )
        if contract.get("format") != "stage-a-relation-contract-v1":
            raise StageAInputError(
                "manual relational proof contract must use "
                "stage-a-relation-contract-v1"
            )
        return
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise StageAInputError(f"manual annotation must be typed JSON: {exc}") from exc
    annotation = _object(payload, f"manual annotation {role}")
    _reject_private_fields(annotation, context=f"manual annotation {role}")
    allowed = {"format", "id", "kind", "target", "rationale", "payload", "note"}
    undeclared = set(annotation) - allowed
    if annotation.get("format") != "stage-b-manual-annotation-v1" or undeclared:
        raise StageAInputError(
            f"manual annotation {role} must use stage-b-manual-annotation-v1 without undeclared fields"
        )
    if not any(key in annotation for key in ("rationale", "payload", "note")):
        raise StageAInputError(f"manual annotation {role} does not state its repair evidence")


def is_stage_a_proof_only_manual_role(role: str) -> bool:
    """Return whether a recorded annotation is visible only to Stage A proof."""

    return role in _STAGE_A_PROOF_ONLY_MANUAL_ROLES


def _reject_private_fields(value: Any, *, context: str) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            normalized = str(key).lower().replace("-", "_")
            if normalized in _PROHIBITED_FIELDS:
                raise StageAInputError(f"{context} contains prohibited provenance field {key!r}")
            if normalized in {"role", "kind", "origin", "provenance_class"} and isinstance(child, str):
                if child.lower().replace("-", "_") in _PROHIBITED_ROLES:
                    raise StageAInputError(f"{context} declares prohibited provenance class {child!r}")
            _reject_private_fields(child, context=context)
    elif isinstance(value, list):
        for child in value:
            _reject_private_fields(child, context=context)


def _reject_private_structured_file(path: Path, *, context: str) -> None:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise StageAInputError(f"{context} must be structured UTF-8 evidence: {exc}") from exc
    values: list[Any] = []
    try:
        values.append(json.loads(text))
    except json.JSONDecodeError:
        for line_number, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                values.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise StageAInputError(
                    f"{context} line {line_number} is not structured JSON: {exc}"
                ) from exc
    for value in values:
        _reject_private_fields(value, context=context)


__all__ = [
    "OPAQUE_STAGE_B_AUDIT_FORMAT",
    "OPAQUE_STAGE_B_BUNDLE_FORMAT",
    "OPAQUE_STAGE_B_CHAIN_FORMAT",
    "OpaqueStageBInput",
    "OpaqueStageBProvenanceChain",
    "build_opaque_stage_b_input_bundle",
    "is_stage_a_proof_only_manual_role",
    "validate_opaque_stage_b_input_bundle",
]

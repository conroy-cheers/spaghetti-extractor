"""Augment a canonical state machine with checked rooted decode proposals."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any, Mapping, Sequence

from ._contract_tools.common import BlockMapping
from ._contract_tools.reference_contract import _semantic_transfer_contract
from .artifact_formats import MACHINE_IR_FORMAT
from .recursive_decode import (
    ROOTED_INSTRUCTION_VIEW_FORMAT,
    discover_rooted_instruction_views,
)
from .reconstruction_ir import export_machine_ir_package
from .stage_b_state_machine import (
    STAGE_B_STATE_MACHINE_FORMAT,
    load_stage_a_reference_contract_binding,
    normalize_stage_a_semantic_transfer,
    normalize_stage_a_semantic_transfers,
    write_stage_b_state_machine,
)
from .stage_binary import BlockSide, StageAInputError, _parse_stage_a_pe
from .util import sha256_bytes, sha256_file, write_json


ROOTED_STATE_MACHINE_AUGMENTATION_FORMAT = (
    "stage-b-rooted-state-machine-augmentation-v1"
)


def augment_state_machine_with_rooted_instruction_views(
    *,
    state_machine: Path,
    machine_ir_manifest: Path,
    original_pe: Path,
    reference_contract: Path,
    out: Path,
    report: Path,
    instruction_budget: int = 65536,
    iteration_budget: int = 32,
    indirect_target_profile: Path | None = None,
    machine_import_profiles: Sequence[Path] = (),
    external_interface_profiles: Sequence[Path] = (),
) -> dict[str, Any]:
    """Add exact one-instruction views for rooted unresolved direct targets.

    Recursive discovery and symbolic transfer generation are proposal logic.
    Every emitted row retains a Stage A reference binding, and the downstream
    machine-IR exporter independently re-decodes the instruction and compares
    its exact bytes with ``original_pe``.
    """

    state_machine = _regular_file(state_machine, "base state machine")
    machine_ir_manifest = _regular_file(
        machine_ir_manifest, "base machine-IR manifest"
    )
    original_pe = _regular_file(original_pe, "original PE")
    reference_contract = _regular_file(
        reference_contract, "reference contract"
    )
    base_rows = _canonical_state_machine_rows(state_machine)
    manifest = _json_object(machine_ir_manifest, "base machine-IR manifest")
    reference = load_stage_a_reference_contract_binding(
        reference_contract, original_pe=original_pe
    )
    if iteration_budget <= 0:
        raise StageAInputError("rooted decode iteration budget must be positive")
    indirect_target_profile = (
        _regular_file(indirect_target_profile, "indirect-target profile")
        if indirect_target_profile is not None
        else None
    )
    binary = _parse_stage_a_pe(original_pe)
    try:
        _validate_manifest_bindings(
            manifest,
            state_machine_sha256=sha256_file(state_machine),
            original_sha256=binary.sha256,
            reference_sha256=reference.sha256,
        )
        merged = list(base_rows)
        current_manifest = manifest
        iterations: list[dict[str, Any]] = []
        all_seed_targets: set[int] = set()
        all_views: list[dict[str, Any]] = []
        all_merges: list[dict[str, Any]] = []
        all_issues: list[dict[str, Any]] = []
        status = "incomplete"
        for iteration_index in range(iteration_budget):
            seeds = _rooted_unresolved_direct_targets(current_manifest)
            if not seeds:
                status = "complete"
                break
            remaining = instruction_budget - len(all_views)
            if remaining <= 0:
                all_issues.append({
                    "status": "incomplete",
                    "code": "total_instruction_budget_exhausted",
                    "message": (
                        "rooted state-machine augmentation exhausted its total "
                        "instruction budget"
                    ),
                    "pending_rvas": seeds,
                })
                break
            existing_rvas = {_transfer_start(row) for row in merged}
            discovery = discover_rooted_instruction_views(
                binary,
                seeds,
                existing_rvas,
                remaining,
            )
            supplemental = [
                _view_transfer(
                    binary=binary,
                    view=view,
                    reference_path=reference_contract,
                    reference_sha256=reference.sha256,
                )
                for view in discovery["views"]
            ]
            all_seed_targets.update(seeds)
            all_views.extend(discovery["views"])
            all_merges.extend(discovery["merge_destinations"])
            all_issues.extend(discovery["issues"])
            iterations.append({
                "index": iteration_index,
                "seed_targets": seeds,
                "decoded_instruction_count": discovery[
                    "decoded_instruction_count"
                ],
                "merge_destinations": len(discovery["merge_destinations"]),
                "issues": len(discovery["issues"]),
            })
            merged = normalize_stage_a_semantic_transfers(
                [*merged, *supplemental]
            )
            if discovery["status"] != "complete":
                break
            if not supplemental:
                all_issues.append({
                    "status": "incomplete",
                    "code": "rooted_decode_made_no_progress",
                    "message": (
                        "rooted direct targets remain but recursive discovery "
                        "produced no new instruction views"
                    ),
                    "pending_rvas": seeds,
                })
                break
            with tempfile.TemporaryDirectory(
                prefix="spaghetti-rooted-state-machine-"
            ) as temporary:
                temporary_root = Path(temporary)
                temporary_state = temporary_root / "state-machine.jsonl"
                temporary_ir = temporary_root / "machine-ir"
                write_stage_b_state_machine(temporary_state, merged)
                export_machine_ir_package(
                    state_machine=temporary_state,
                    original_pe=original_pe,
                    reference_contract=reference_contract,
                    indirect_target_profile=indirect_target_profile,
                    machine_import_profiles=machine_import_profiles,
                    external_interface_profiles=external_interface_profiles,
                    out=temporary_ir,
                )
                current_manifest = _json_object(
                    temporary_ir / "machine-ir-manifest.json",
                    "iterated machine-IR manifest",
                )
        else:
            pending = _rooted_unresolved_direct_targets(current_manifest)
            if pending:
                all_issues.append({
                    "status": "incomplete",
                    "code": "rooted_decode_iteration_budget_exhausted",
                    "message": (
                        "rooted state-machine augmentation did not close direct "
                        "control within its iteration budget"
                    ),
                    "pending_rvas": pending,
                })
    finally:
        binary.pe.close()

    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    write_stage_b_state_machine(out, merged)

    final_seeds = _rooted_unresolved_direct_targets(current_manifest)
    status = (
        "complete"
        if not final_seeds and not all_issues
        else "incomplete"
    )
    discovery = {
        "format": ROOTED_INSTRUCTION_VIEW_FORMAT,
        "status": status,
        "instruction_budget": instruction_budget,
        "iteration_budget": iteration_budget,
        "iterations": iterations,
        "views": all_views,
        "merge_destinations": all_merges,
        "issues": all_issues,
        "remaining_rooted_direct_targets": final_seeds,
    }
    payload = {
        "format": ROOTED_STATE_MACHINE_AUGMENTATION_FORMAT,
        "status": status,
        "inputs": {
            "state_machine_sha256": sha256_file(state_machine),
            "machine_ir_manifest_sha256": sha256_file(machine_ir_manifest),
            "original_pe_sha256": sha256_file(original_pe),
            "reference_contract_sha256": reference.sha256,
        },
        "output": {
            "path": out.name,
            "sha256": sha256_file(out),
        },
        "discovery": discovery,
        "counts": {
            "iterations": len(iterations),
            "seed_targets": len(all_seed_targets),
            "base_transfers": len(base_rows),
            "supplemental_transfers": len(all_views),
            "output_transfers": len(merged),
            "merge_destinations": len(all_merges),
            "remaining_rooted_direct_targets": len(final_seeds),
            "issues": len(all_issues),
        },
        "trust": {
            "executes_original_binary": False,
            "recursive_decode_is_proposal_only": True,
            "exact_pe_binding_required_downstream": True,
            "semantic_binding_required_downstream": True,
        },
    }
    report = Path(report)
    report.parent.mkdir(parents=True, exist_ok=True)
    write_json(report, payload)
    return payload


def _view_transfer(
    *,
    binary: Any,
    view: Mapping[str, Any],
    reference_path: Path,
    reference_sha256: str,
) -> dict[str, Any]:
    start = _u32(view.get("rva_start"), "rooted view start")
    end = _u32(view.get("rva_end"), "rooted view end")
    if end <= start:
        raise StageAInputError("rooted view span is empty")
    encoded = view.get("bytes")
    if not isinstance(encoded, str):
        raise StageAInputError("rooted view byte proposal is malformed")
    try:
        proposed_bytes = bytes.fromhex(encoded)
    except ValueError as exc:
        raise StageAInputError("rooted view byte proposal is malformed") from exc
    image_bytes = bytes(binary.pe.get_data(start, end - start))
    if len(proposed_bytes) != end - start or proposed_bytes != image_bytes:
        raise StageAInputError(
            f"rooted view 0x{start:x}-0x{end:x} differs from the original PE"
        )
    identity = f"rooted-view-{start:08x}-{end:08x}"
    span = BlockSide(start, end)
    mapped = BlockMapping(
        id=identity,
        original=span,
        candidate=span,
        kind="code",
        reachable=True,
        invariant_checked=False,
        source={
            "source": {
                "kind": "rooted_recursive_decode_view",
                "proposal_format": ROOTED_INSTRUCTION_VIEW_FORMAT,
                "control": view.get("control"),
                "provenance": view.get("provenance"),
            }
        },
    )
    raw = _semantic_transfer_contract(
        binary,
        mapped,
        identity,
        {
            "format": "stage-a-reference-contract-v1",
            "path": reference_path.name,
            "sha256": reference_sha256,
        },
        semantic_side=span,
        semantic_block_id=identity,
    )
    transfer_sha256 = sha256_bytes(_canonical_json(raw))
    return normalize_stage_a_semantic_transfer(
        raw,
        reference_contract_sha256=reference_sha256,
        semantic_transfer_sha256=transfer_sha256,
    )


def _rooted_unresolved_direct_targets(manifest: Mapping[str, Any]) -> list[int]:
    control = _mapping(manifest.get("control"), "machine-IR control inventory")
    reachability = _mapping(
        control.get("reachability"), "machine-IR reachability inventory"
    )
    raw_reachable = reachability.get("reachable_units")
    raw_targets = control.get("direct_targets")
    if not isinstance(raw_reachable, list) or not isinstance(raw_targets, list):
        raise StageAInputError("machine-IR rooted control inventory is malformed")
    reachable = {
        str(value)
        for value in raw_reachable
        if isinstance(value, str) and value
    }
    return sorted({
        _u32(row.get("target_rva"), "unresolved direct target")
        for row in raw_targets
        if isinstance(row, Mapping)
        and row.get("status") == "incomplete"
        and row.get("source_unit_id") in reachable
    })


def _validate_manifest_bindings(
    manifest: Mapping[str, Any],
    *,
    state_machine_sha256: str,
    original_sha256: str,
    reference_sha256: str,
) -> None:
    if manifest.get("format") != MACHINE_IR_FORMAT:
        raise StageAInputError("base machine-IR manifest format is unsupported")
    inputs = _mapping(manifest.get("inputs"), "machine-IR inputs")
    state = _mapping(inputs.get("state_machine"), "machine-IR state-machine input")
    original = _mapping(manifest.get("binary"), "machine-IR binary inventory")
    reference = _mapping(
        inputs.get("reference_contract"), "machine-IR reference input"
    )
    expected = (
        (state.get("sha256"), state_machine_sha256, "state machine"),
        (original.get("sha256"), original_sha256, "original PE"),
        (reference.get("sha256"), reference_sha256, "reference contract"),
    )
    for observed, wanted, label in expected:
        if observed != wanted:
            raise StageAInputError(f"machine-IR {label} binding differs")


def _canonical_state_machine_rows(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), 1
    ):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise StageAInputError(
                f"invalid state-machine JSON on line {line_number}: {exc}"
            ) from exc
        row = _mapping(value, f"state-machine line {line_number}")
        if row.get("stage_b_format") != STAGE_B_STATE_MACHINE_FORMAT:
            raise StageAInputError(
                f"state-machine line {line_number} is not canonical"
            )
        normalized = normalize_stage_a_semantic_transfer(dict(row))
        if normalized.get("contract_sha256") != row.get("contract_sha256"):
            raise StageAInputError(
                f"state-machine line {line_number} has a stale contract digest"
            )
        rows.append(dict(row))
    if not rows:
        raise StageAInputError("base state machine is empty")
    return rows


def _regular_file(path: Path, context: str) -> Path:
    path = Path(path).resolve()
    if not path.is_file() or path.is_symlink():
        raise StageAInputError(f"{context} must be a regular non-symlink file")
    return path


def _json_object(path: Path, context: str) -> dict[str, Any]:
    try:
        return _mapping(json.loads(path.read_text(encoding="utf-8")), context)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise StageAInputError(f"cannot read {context}: {exc}") from exc


def _mapping(value: Any, context: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise StageAInputError(f"{context} must be an object")
    return dict(value)


def _transfer_start(row: Mapping[str, Any]) -> int:
    original = _mapping(row.get("original"), "state-machine original span")
    return _u32(original.get("rva_start"), "state-machine transfer start")


def _u32(value: Any, context: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value < 2**32
    ):
        raise StageAInputError(f"{context} must be an unsigned 32-bit integer")
    return value


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


__all__ = [
    "ROOTED_STATE_MACHINE_AUGMENTATION_FORMAT",
    "augment_state_machine_with_rooted_instruction_views",
]

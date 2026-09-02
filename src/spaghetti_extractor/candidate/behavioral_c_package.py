"""Package assembly and receipts for faithful behavioral-C output."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable, Mapping

from ..artifacts.artifact_set import canonical_sha256_v3
from ..components.capabilities import (
    spx_capability_backend_header,
    spx_capability_backend_source,
)
from ..semantic_objects.semantic_object import SemanticObjectV1
from ..transfer.model import TransferPlanError, _Transfer
from ..transfer.operations import runtime_provider_requirements_v2
from ..transfer.plan import load_executable_transfer_plan
from ..transfer.definedness import definedness_operation_coverage_v2
from ..transfer.evaluator import concrete_operation_coverage_v2
from ..transfer.interpretation import operation_coverage_matrix_v2
from ..transfer.provenance_coverage import reference_operation_coverage_v2
from ..transfer.z3_domain import z3_operation_coverage_v2
from ..util import sha256_file, write_json
from .formats import (
    BEHAVIORAL_C_BUILD_MANIFEST_FORMAT,
    BEHAVIORAL_C_COVERAGE_FORMAT,
    BEHAVIORAL_C_LAYOUT_INTENT_FORMAT,
    BEHAVIORAL_C_LOWERING_FORMAT,
    BEHAVIORAL_C_PACKAGE_FORMAT,
    BEHAVIORAL_C_PLAN_FORMAT,
    BEHAVIORAL_C_SOURCE_MAP_FORMAT,
)
from .atomics import (
    spx_atomics_backend_header,
    spx_atomics_header,
    spx_atomics_source,
)
from .behavioral_c_layout import build_behavioral_c_plan
from .behavioral_c_model import BehavioralCLayoutIntent, BehavioralCPlan
from .behavioral_c_render import (
    behavioral_c_operation_coverage_v2,
    behavioral_c_header,
    behavioral_c_translation_units,
)
from ..transfer.runtime_abi import exact_runtime_header


def write_spx_behavioral_c_package(
    *,
    transfer_plan: Path,
    out: Path,
    entry_rvas: Iterable[int] = (),
    layout_intent: Path | None = None,
    _semantic_object_binding: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Render one serialized executable transfer plan as faithful C."""

    transfer_plan = Path(transfer_plan)
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    transfer_payload, transfers = load_executable_transfer_plan(transfer_plan)
    unit_inventory = list(transfer_payload["unit_inventory"])
    blockers = list(transfer_payload["semantic_blockers"])
    intent, intent_binding = _load_layout_intent(layout_intent)
    plan = build_behavioral_c_plan(
        transfers,
        entry_rvas=entry_rvas,
        intent=intent,
    )
    translation_units, source_map_rows = behavioral_c_translation_units(
        transfers, plan
    )

    files = {
        "runtime_header": out / "state-machine-runtime.h",
        "behavioral_header": out / "behavioral-c.h",
        "capability_backend_header": out / "spx-capability-backend.h",
        "capability_backend_source": out / "spx-capability-backend.c",
        "atomics_header": out / "spx-atomics.h",
        "atomics_backend_header": out / "spx-atomics-backend.h",
        "atomics_source": out / "spx-atomics.c",
    }
    files["runtime_header"].write_text(exact_runtime_header(), encoding="ascii")
    files["behavioral_header"].write_text(behavioral_c_header(plan), encoding="ascii")
    for filename, source in translation_units.items():
        role = (
            "behavioral_dispatch"
            if filename == "behavioral-dispatch.c"
            else "behavioral_support"
            if filename == "behavioral-support.c"
            else "behavioral_function:" + filename[14:-2]
        )
        files[role] = out / filename
        files[role].write_text(source, encoding="ascii")
    files["capability_backend_header"].write_text(
        spx_capability_backend_header(), encoding="ascii"
    )
    files["capability_backend_source"].write_text(
        spx_capability_backend_source(), encoding="ascii"
    )
    files["atomics_header"].write_text(spx_atomics_header(), encoding="ascii")
    files["atomics_backend_header"].write_text(
        spx_atomics_backend_header(), encoding="ascii"
    )
    files["atomics_source"].write_text(spx_atomics_source(), encoding="ascii")

    machine_sha = str(transfer_payload["bindings"]["machine_ir_sha256"])
    transfer_plan_sha = sha256_file(transfer_plan)
    plan_payload = _plan_payload(
        plan,
        machine_ir_sha256=machine_sha,
        layout_intent=intent_binding,
    )
    write_json(out / "behavioral-c-plan.json", plan_payload)
    source_map = {
        "format": BEHAVIORAL_C_SOURCE_MAP_FORMAT,
        "status": "complete",
        "machine_ir_sha256": machine_sha,
        "executable_transfer_plan_sha256": transfer_plan_sha,
        "units": [source_map_rows[rva] for rva in sorted(source_map_rows)],
        "proof_authority": False,
    }
    write_json(out / "behavioral-c-source-map.json", source_map)
    coverage = _coverage_payload(
        unit_inventory=unit_inventory,
        transfers=transfers,
        plan=plan,
        blockers=blockers,
        machine_ir_sha256=machine_sha,
        source_spans=source_map_rows,
    )
    write_json(out / "behavioral-c-coverage.json", coverage)
    lowering = _lowering_payload(
        transfers=transfers,
        machine_ir_sha256=machine_sha,
        plan_sha256=sha256_file(out / "behavioral-c-plan.json"),
        source_sha256=canonical_sha256_v3([
            {"path": path.name, "sha256": sha256_file(path)}
            for role, path in sorted(files.items())
            if role.startswith("behavioral_") and path.suffix == ".c"
        ]),
    )
    write_json(out / "behavioral-c-lowering.json", lowering)
    required_providers = _required_runtime_providers(transfers)
    build_manifest_core = {
        "format": BEHAVIORAL_C_BUILD_MANIFEST_FORMAT,
        "status": "complete",
        "executable_transfer_plan_sha256": transfer_plan_sha,
        "behavioral_c_plan_sha256": sha256_file(out / "behavioral-c-plan.json"),
        "sources": [
            {"role": role, "path": path.name, "sha256": sha256_file(path)}
            for role, path in sorted(files.items())
        ],
        "required_runtime_providers": required_providers,
        "translation_unit_count": len(translation_units),
        "function_translation_unit_count": len(plan.functions),
        "shared_support_translation_unit_count": 1,
        "proof_authority": False,
    }
    build_manifest = {
        **build_manifest_core,
        "manifest_sha256": canonical_sha256_v3(build_manifest_core),
    }
    write_json(out / "behavioral-c-build-manifest.json", build_manifest)
    lower_complete = coverage["status"] == "complete" and lowering["status"] == "complete"
    package = {
        "format": BEHAVIORAL_C_PACKAGE_FORMAT,
        "status": "ready" if lower_complete else "incomplete",
        "executable_transfer_plan": {
            "path": transfer_plan.name,
            "sha256": transfer_plan_sha,
            "plan_sha256": transfer_payload["plan_sha256"],
            "machine_ir_sha256": machine_sha,
        },
        "input_mode": "executable_transfer_plan_v2",
        "representation": "direct_structured_behavioral_c_v1",
        "semantic_lowering": "canonical_checked_transfer_ir_v2",
        "sources": [
            {"role": role, "path": path.name, "sha256": sha256_file(path)}
            for role, path in files.items()
        ],
        "artifacts": {
            name: {"path": path.name, "sha256": sha256_file(path)}
            for name, path in {
                "plan": out / "behavioral-c-plan.json",
                "coverage": out / "behavioral-c-coverage.json",
                "lowering": out / "behavioral-c-lowering.json",
                "source_map": out / "behavioral-c-source-map.json",
                "build_manifest": out / "behavioral-c-build-manifest.json",
            }.items()
        },
        "counts": coverage["counts"],
        "constraints": {
            "original_instruction_bytes_embedded": False,
            "runtime_instruction_decoder": False,
            "semantic_opcode_tables": False,
            "per_transfer_pc_dispatch_loop": False,
            "operator_authored_c_bodies": False,
        },
        "blockers": blockers,
        "authority": (
            "generated faithful behavioral C; provider qualification and native "
            "realization separately bind runtime and executable object evidence"
        ),
    }
    if _semantic_object_binding is not None:
        package["input_mode"] = "semantic_object_v1"
        package["semantic_object"] = dict(_semantic_object_binding)
    write_json(out / "behavioral-c-package.json", package)
    return package


def write_spx_behavioral_c_package_from_semantic_object(
    *,
    semantic_object: Path,
    out: Path,
    entry_rvas: Iterable[int] = (),
    layout_intent: Path | None = None,
) -> dict[str, Any]:
    """Render the exact transfer member of a checked semantic-object package."""

    source = Path(semantic_object)
    package = SemanticObjectV1.load(source)
    return write_spx_behavioral_c_package(
        transfer_plan=package.transfer_plan_path,
        out=out,
        entry_rvas=entry_rvas,
        layout_intent=layout_intent,
        _semantic_object_binding={
            "path": source.name,
            "sha256": sha256_file(source),
            "semantic_object_sha256": package.identity,
            "transfer_plan_sha256": str(package.transfer_plan["plan_sha256"]),
        },
    )


def _load_layout_intent(
    path: Path | None,
) -> tuple[BehavioralCLayoutIntent, dict[str, Any] | None]:
    if path is None:
        return BehavioralCLayoutIntent(), None
    path = Path(path)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise TransferPlanError(
            f"cannot read behavioral-C layout intent {path}: {exc}",
            code="malformed_behavioral_c_layout_intent",
        ) from exc
    if not isinstance(raw, Mapping):
        raise TransferPlanError(
            "behavioral-C layout intent must be a JSON object",
            code="malformed_behavioral_c_layout_intent",
        )
    intent = BehavioralCLayoutIntent.from_payload(raw)
    return intent, {
        "format": BEHAVIORAL_C_LAYOUT_INTENT_FORMAT,
        "path": path.name,
        "sha256": sha256_file(path),
    }


def _plan_payload(
    plan: BehavioralCPlan,
    *,
    machine_ir_sha256: str,
    layout_intent: dict[str, Any] | None,
) -> dict[str, Any]:
    return {
        "format": BEHAVIORAL_C_PLAN_FORMAT,
        "status": "complete",
        "machine_ir_sha256": machine_ir_sha256,
        "layout_intent": layout_intent,
        "roots": list(plan.roots),
        "forced_labels": list(plan.forced_labels),
        "functions": [function.payload() for function in plan.functions],
        "counts": {
            "functions": len(plan.functions),
            "entries": sum(len(function.entries) for function in plan.functions),
            "owned_units": len(plan.unit_rvas),
        },
        "ownership": "exact_nonoverlapping_machine_unit_partition_v1",
        "control_recovery": (
            "checked edges with direct sequences, structured branches, and labels for "
            "multi-entry or residual control"
        ),
        "proof_authority": False,
    }


def _coverage_payload(
    *,
    unit_inventory: list[dict[str, Any]],
    transfers: tuple[_Transfer, ...],
    plan: BehavioralCPlan,
    blockers: list[dict[str, Any]],
    machine_ir_sha256: str,
    source_spans: dict[int, dict[str, object]],
) -> dict[str, Any]:
    required_ids = sorted(str(row.get("unit_id")) for row in unit_inventory)
    lowered_ids = sorted(row.identity for row in transfers)
    required_rvas = sorted(
        int(row["rva_start"]) for row in unit_inventory
    )
    owned_rvas = sorted(plan.unit_rvas)
    missing_ids = sorted(set(required_ids) - set(lowered_ids))
    extra_ids = sorted(set(lowered_ids) - set(required_ids))
    missing_rvas = sorted(set(required_rvas) - set(owned_rvas))
    extra_rvas = sorted(set(owned_rvas) - set(required_rvas))
    exact = not blockers and not missing_ids and not extra_ids and not missing_rvas and not extra_rvas
    operation_coverage = operation_coverage_matrix_v2((
        behavioral_c_operation_coverage_v2(),
        concrete_operation_coverage_v2(),
        definedness_operation_coverage_v2(),
        reference_operation_coverage_v2(),
        z3_operation_coverage_v2(),
    ))
    return {
        "format": BEHAVIORAL_C_COVERAGE_FORMAT,
        "status": "complete" if exact else "incomplete",
        "machine_ir_sha256": machine_ir_sha256,
        "counts": {
            "required_units": len(required_ids),
            "lowered_units": len(lowered_ids),
            "owned_units": len(owned_rvas),
            "functions": len(plan.functions),
            "blockers": len(blockers),
        },
        "required_unit_ids": required_ids,
        "lowered_unit_ids": lowered_ids,
        "missing_unit_ids": missing_ids,
        "extra_unit_ids": extra_ids,
        "missing_unit_rvas": missing_rvas,
        "extra_unit_rvas": extra_rvas,
        "source_spans": [dict(span) for _rva, span in sorted(source_spans.items())],
        "operation_coverage": operation_coverage,
        "blockers": blockers,
        "acceptance": "every sanitized machine-IR unit is lowered and owned exactly once",
        "proof_authority": False,
    }


def _lowering_payload(
    *,
    transfers: tuple[_Transfer, ...],
    machine_ir_sha256: str,
    plan_sha256: str,
    source_sha256: str,
) -> dict[str, Any]:
    return {
        "format": BEHAVIORAL_C_LOWERING_FORMAT,
        "status": "complete",
        "machine_ir_sha256": machine_ir_sha256,
        "behavioral_c_plan_sha256": plan_sha256,
        "behavioral_c_source_sha256": source_sha256,
        "canonical_ir": "checked_transfer_ir_v2",
        "source_form": "direct_structured_behavioral_c_v1",
        "word_ops": sorted({node.op for row in transfers for node in row.nodes}),
        "action_ops": sorted({action.op for row in transfers for action in row.actions}),
        "typed_x87_operation_count": sum(len(row.x87_operations) for row in transfers),
        "effect_order": "canonical_scheduled_action_order_v1",
        "machine_unit_input_snapshot": "before_each_owned_unit_v1",
        "proof_authority": False,
    }


def _required_runtime_providers(transfers: tuple[_Transfer, ...]) -> list[str]:
    return runtime_provider_requirements_v2(transfers, layer="behavioral_c")


__all__ = ["write_spx_behavioral_c_package"]

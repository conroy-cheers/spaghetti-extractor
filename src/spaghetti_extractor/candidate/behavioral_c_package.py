"""Package assembly and receipts for faithful behavioral-C output."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable, Mapping

from ..artifacts.formats import (
    BEHAVIORAL_C_COMPLETION_FORMAT,
    BEHAVIORAL_C_COVERAGE_FORMAT,
    BEHAVIORAL_C_LAYOUT_INTENT_FORMAT,
    BEHAVIORAL_C_LOWERING_FORMAT,
    BEHAVIORAL_C_PACKAGE_FORMAT,
    BEHAVIORAL_C_PLAN_FORMAT,
    BEHAVIORAL_C_RUNTIME_QUALIFICATION_FORMAT,
)
from ..components.capabilities import (
    spx_capability_backend_header,
    spx_capability_backend_source,
)
from ..util import sha256_file, write_json
from .atomics import (
    spx_atomics_backend_header,
    spx_atomics_header,
    spx_atomics_source,
)
from .behavioral_c_layout import build_behavioral_c_plan
from .behavioral_c_model import BehavioralCLayoutIntent, BehavioralCPlan
from .behavioral_c_render import behavioral_c_header, behavioral_c_source
from .interpreter_model import CandidateInterpreterError, _Transfer
from .interpreter_package import (
    _adapt_machine_ir_rows,
    _compile_interpreter_rows,
)
from .interpreter_values import _read_jsonl
from .runtime_abi import exact_runtime_header


def write_spx_behavioral_c_package(
    *,
    machine_ir: Path,
    out: Path,
    entry_rvas: Iterable[int] = (),
    layout_intent: Path | None = None,
    runtime_qualification: Path | None = None,
) -> dict[str, Any]:
    """Lower sanitized machine IR to direct C and emit fail-closed receipts."""

    machine_ir = Path(machine_ir)
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    input_rows = _read_jsonl(machine_ir)
    semantic_rows = _adapt_machine_ir_rows(input_rows)
    transfers, blockers = _compile_interpreter_rows(
        semantic_rows, collect_blockers=True
    )
    intent, intent_binding = _load_layout_intent(layout_intent)
    plan = build_behavioral_c_plan(
        transfers,
        entry_rvas=entry_rvas,
        intent=intent,
    )
    source, source_spans = behavioral_c_source(transfers, plan)

    files = {
        "runtime_header": out / "state-machine-runtime.h",
        "behavioral_header": out / "behavioral-c.h",
        "behavioral_source": out / "behavioral-c.c",
        "capability_backend_header": out / "spx-capability-backend.h",
        "capability_backend_source": out / "spx-capability-backend.c",
        "atomics_header": out / "spx-atomics.h",
        "atomics_backend_header": out / "spx-atomics-backend.h",
        "atomics_source": out / "spx-atomics.c",
    }
    files["runtime_header"].write_text(exact_runtime_header(), encoding="ascii")
    files["behavioral_header"].write_text(behavioral_c_header(plan), encoding="ascii")
    files["behavioral_source"].write_text(source, encoding="ascii")
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

    machine_sha = sha256_file(machine_ir)
    plan_payload = _plan_payload(
        plan,
        machine_ir_sha256=machine_sha,
        layout_intent=intent_binding,
    )
    write_json(out / "behavioral-c-plan.json", plan_payload)
    coverage = _coverage_payload(
        input_rows=input_rows,
        transfers=transfers,
        plan=plan,
        blockers=blockers,
        machine_ir_sha256=machine_sha,
        source_spans=source_spans,
    )
    write_json(out / "behavioral-c-coverage.json", coverage)
    lowering = _lowering_payload(
        transfers=transfers,
        machine_ir_sha256=machine_sha,
        plan_sha256=sha256_file(out / "behavioral-c-plan.json"),
        source_sha256=sha256_file(files["behavioral_source"]),
    )
    write_json(out / "behavioral-c-lowering.json", lowering)
    required_providers = _required_runtime_providers(transfers)
    runtime_receipt = _runtime_qualification_payload(
        path=runtime_qualification,
        machine_ir_sha256=machine_sha,
        required_providers=required_providers,
    )
    write_json(out / "behavioral-c-runtime-qualification.json", runtime_receipt)

    lower_complete = coverage["status"] == "complete" and lowering["status"] == "complete"
    runtime_complete = runtime_receipt["status"] == "complete"
    completion_blockers = []
    if not lower_complete:
        completion_blockers.append("direct_c_lowering_incomplete")
    if not runtime_complete:
        completion_blockers.append("exact_runtime_not_qualified")
    completion = {
        "format": BEHAVIORAL_C_COMPLETION_FORMAT,
        "status": "complete" if not completion_blockers else "incomplete",
        "complete": not completion_blockers,
        "machine_ir_sha256": machine_sha,
        "owned_units": [
            {"id": transfer.identity, "rva_start": transfer.rva_start}
            for transfer in transfers
        ],
        "behavioral_c_plan_sha256": sha256_file(out / "behavioral-c-plan.json"),
        "behavioral_c_lowering_sha256": sha256_file(out / "behavioral-c-lowering.json"),
        "behavioral_c_coverage_sha256": sha256_file(out / "behavioral-c-coverage.json"),
        "runtime_qualification_sha256": sha256_file(
            out / "behavioral-c-runtime-qualification.json"
        ),
        "blockers": completion_blockers,
        "acceptance": (
            "all checked machine units have one direct behavioral-C owner and all "
            "required exact runtime providers are qualified"
        ),
        "proof_authority": False,
    }
    write_json(out / "behavioral-c-completion.json", completion)
    package = {
        "format": BEHAVIORAL_C_PACKAGE_FORMAT,
        "status": "ready" if lower_complete else "incomplete",
        "completion_status": completion["status"],
        "machine_ir": {"path": machine_ir.name, "sha256": machine_sha},
        "input_mode": "sanitized_machine_ir_v3",
        "representation": "direct_structured_behavioral_c_v1",
        "semantic_lowering": "canonical_checked_transfer_ir_v1",
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
                "runtime_qualification": out / "behavioral-c-runtime-qualification.json",
                "completion": out / "behavioral-c-completion.json",
            }.items()
        },
        "counts": coverage["counts"],
        "constraints": {
            "original_instruction_bytes_embedded": False,
            "runtime_instruction_decoder": False,
            "semantic_opcode_tables": False,
            "per_transfer_pc_interpreter_loop": False,
            "operator_authored_c_bodies": False,
        },
        "blockers": blockers,
        "authority": (
            "generated faithful behavioral C; completion additionally requires the "
            "content-bound runtime qualification receipt"
        ),
    }
    write_json(out / "behavioral-c-package.json", package)
    return package


def _load_layout_intent(
    path: Path | None,
) -> tuple[BehavioralCLayoutIntent, dict[str, Any] | None]:
    if path is None:
        return BehavioralCLayoutIntent(), None
    path = Path(path)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CandidateInterpreterError(
            f"cannot read behavioral-C layout intent {path}: {exc}",
            code="malformed_behavioral_c_layout_intent",
        ) from exc
    if not isinstance(raw, Mapping):
        raise CandidateInterpreterError(
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
    input_rows: list[dict[str, Any]],
    transfers: tuple[_Transfer, ...],
    plan: BehavioralCPlan,
    blockers: list[dict[str, Any]],
    machine_ir_sha256: str,
    source_spans: dict[int, tuple[int, int]],
) -> dict[str, Any]:
    required_ids = sorted(str(row.get("id")) for row in input_rows)
    lowered_ids = sorted(row.identity for row in transfers)
    required_rvas = sorted(
        int(row["source"]["original"]["rva_start"]) for row in input_rows
    )
    owned_rvas = sorted(plan.unit_rvas)
    missing_ids = sorted(set(required_ids) - set(lowered_ids))
    extra_ids = sorted(set(lowered_ids) - set(required_ids))
    missing_rvas = sorted(set(required_rvas) - set(owned_rvas))
    extra_rvas = sorted(set(owned_rvas) - set(required_rvas))
    exact = not blockers and not missing_ids and not extra_ids and not missing_rvas and not extra_rvas
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
        "source_spans": [
            {"rva": rva, "line_start": span[0], "line_end": span[1]}
            for rva, span in sorted(source_spans.items())
        ],
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
        "canonical_ir": "checked_transfer_ir_v1",
        "source_form": "direct_structured_behavioral_c_v1",
        "word_ops": sorted({node.op for row in transfers for node in row.nodes}),
        "action_ops": sorted({action.op for row in transfers for action in row.actions}),
        "typed_x87_operation_count": sum(len(row.x87_operations) for row in transfers),
        "effect_order": "canonical_scheduled_action_order_v1",
        "machine_unit_input_snapshot": "before_each_owned_unit_v1",
        "proof_authority": False,
    }


def _required_runtime_providers(transfers: tuple[_Transfer, ...]) -> list[str]:
    providers: set[str] = set()
    for transfer in transfers:
        node_ops = {node.op for node in transfer.nodes}
        action_ops = {action.op for action in transfer.actions}
        if "load" in node_ops:
            providers.add("memory.read")
        if action_ops & {"memory_write", "rep_movsd", "rep_movs", "rep_stosd", "rep_stos", "rep_scas"}:
            providers.update({"memory.read", "memory.write"})
        if transfer.calls:
            providers.add("call.dispatch")
        if action_ops & {"atomic_compare_exchange", "atomic_exchange"}:
            providers.add("atomic.rmw")
        if "typed_x87" in action_ops:
            providers.add("x87.typed_exact")
        if node_ops & {"undefined_bv", "undefined_flag"}:
            providers.add("definedness.choice")
        if "outcome_indirect" in action_ops:
            providers.add("code_target.resolve")
    return sorted(providers)


def _runtime_qualification_payload(
    *,
    path: Path | None,
    machine_ir_sha256: str,
    required_providers: list[str],
) -> dict[str, Any]:
    if path is None:
        return {
            "format": BEHAVIORAL_C_RUNTIME_QUALIFICATION_FORMAT,
            "status": "incomplete" if required_providers else "complete",
            "machine_ir_sha256": machine_ir_sha256,
            "required_providers": required_providers,
            "qualified_providers": [],
            "missing_providers": required_providers,
            "qualification_input": None,
            "native_ingress_plan_sha256": None,
            "qualified_native_ingress_features": [],
            "qualified_private_stack_bytes": 0,
            "proof_authority": False,
        }
    path = Path(path)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CandidateInterpreterError(
            f"cannot read exact runtime qualification {path}: {exc}",
            code="behavioral_c_runtime_qualification_invalid",
        ) from exc
    if not isinstance(raw, Mapping) or raw.get("format") != BEHAVIORAL_C_RUNTIME_QUALIFICATION_FORMAT:
        raise CandidateInterpreterError(
            "exact runtime qualification has an unsupported format",
            code="behavioral_c_runtime_qualification_invalid",
        )
    qualified_raw = raw.get("qualified_providers")
    if not isinstance(qualified_raw, list) or any(
        not isinstance(item, str) for item in qualified_raw
    ):
        raise CandidateInterpreterError(
            "exact runtime qualification has an invalid provider inventory",
            code="behavioral_c_runtime_qualification_invalid",
        )
    qualified = sorted(set(qualified_raw))
    ingress_features_raw = raw.get("qualified_native_ingress_features", [])
    if not isinstance(ingress_features_raw, list) or any(
        not isinstance(item, str) for item in ingress_features_raw
    ):
        raise CandidateInterpreterError(
            "exact runtime qualification has an invalid native-ingress feature inventory",
            code="behavioral_c_runtime_qualification_invalid",
        )
    ingress_features = sorted(set(ingress_features_raw))
    ingress_plan_sha256 = raw.get("native_ingress_plan_sha256")
    if ingress_plan_sha256 is not None and (
        not isinstance(ingress_plan_sha256, str)
        or len(ingress_plan_sha256) != 64
        or any(character not in "0123456789abcdef" for character in ingress_plan_sha256)
    ):
        raise CandidateInterpreterError(
            "exact runtime qualification has an invalid native-ingress plan binding",
            code="behavioral_c_runtime_qualification_invalid",
        )
    qualified_stack = raw.get("qualified_private_stack_bytes", 0)
    if (
        not isinstance(qualified_stack, int)
        or isinstance(qualified_stack, bool)
        or not 0 <= qualified_stack <= 0xFFFFFFFF
    ):
        raise CandidateInterpreterError(
            "exact runtime qualification has an invalid private-stack extent",
            code="behavioral_c_runtime_qualification_invalid",
        )
    missing = sorted(set(required_providers) - set(qualified))
    input_machine_sha = raw.get("machine_ir_sha256")
    binding_matches = input_machine_sha in {None, machine_ir_sha256}
    complete = raw.get("status") == "complete" and not missing and binding_matches
    return {
        "format": BEHAVIORAL_C_RUNTIME_QUALIFICATION_FORMAT,
        "status": "complete" if complete else "incomplete",
        "machine_ir_sha256": machine_ir_sha256,
        "required_providers": required_providers,
        "qualified_providers": qualified,
        "missing_providers": missing,
        "qualification_input": {"path": path.name, "sha256": sha256_file(path)},
        "native_ingress_plan_sha256": ingress_plan_sha256,
        "qualified_native_ingress_features": ingress_features,
        "qualified_private_stack_bytes": qualified_stack,
        "input_binding_matches": binding_matches,
        "proof_authority": False,
    }


__all__ = ["write_spx_behavioral_c_package"]

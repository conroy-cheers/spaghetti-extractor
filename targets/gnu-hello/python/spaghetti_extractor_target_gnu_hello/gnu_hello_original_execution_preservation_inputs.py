"""Derive exact original-execution preservation inputs or report blockers.

The production adapter owns preservation closure.  It derives the finite
target and frontier inventories from exact generated artifacts and never
accepts a preassembled preservation family, report status, or declaration name
as proof authority.  Until the checked semantic artifacts expose enough
post-state evidence, it emits a deterministic non-authorizing frontier rather
than the final preservation-input document.
"""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, Mapping

from spaghetti_extractor.errors import StageAInputError
from .gnu_hello_original_execution_evidence import (
    ORIGINAL_EXECUTION_PRESERVATION_INPUTS_FORMAT,
    LeanRef,
    sha256_file,
)


ORIGINAL_EXECUTION_PRESERVATION_CONTEXT_FORMAT = (
    "stage-a-original-execution-preservation-context-v1"
)
ORIGINAL_EXECUTION_PRESERVATION_FRONTIER_FORMAT = (
    "stage-a-original-execution-preservation-frontier-v1"
)

_COMBINED_FORMAT = (
    "stage-a-original-combined-execution-inventory-declarations-v1"
)
_EFFECTS_FORMAT = "stage-a-gnu-hello-source-transition-index-declarations-v1"
_TRANSITION_FORMAT = "stage-a-gnu-hello-source-transition-index-v1"
_MIXED_FORMAT = "stage-a-interpreter-mixed-original-v1"
_WRITABLE_FORMAT = (
    "stage-a-relocated-writable-static-pointer-slot-authorities-v2"
)
_REGISTER_FORMAT = "stage-a-register-indirect-control-authorities-v1"
_STACK_FORMAT = "stage-a-original-stack-dynamic-control-closure-v1"

_GNU_TARGET_COUNT = 3490
_GNU_FRONTIER_COUNTS = {
    "writable_static_slot": 19,
    "register_target": 9,
    "stack_dynamic": 3,
}
_GNU_STATIC_WORD_COUNT = 3

_LEAN_LOCAL = re.compile(r"[A-Za-z_][A-Za-z0-9_']*\Z")
_LEAN_NAMESPACE = re.compile(
    r"StageA\.[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")

FrontierKind = Literal[
    "writable_static_slot", "register_target", "stack_dynamic"
]


class OriginalExecutionPreservationInputsError(StageAInputError):
    """The exact preservation-input inventory is incomplete or inconsistent."""


@dataclass(frozen=True)
class PreservationTarget:
    target_id: int
    source_rva: int
    kind: str
    effect_refs: tuple[LeanRef, ...]
    certificate: LeanRef


@dataclass(frozen=True)
class PreservationFrontier:
    category: FrontierKind
    source_rva: int
    source_target_id: int
    requirement_index: int
    static_authority: LeanRef


@dataclass(frozen=True)
class GeneratedPreservationFrontier:
    manifest: Path
    target_count: int
    frontier_count: int
    missing_target_cases: int


def generate_gnu_hello_original_execution_preservation_inputs(
    out: Path | str,
    *,
    combined_inventory_manifest: Path | str,
    source_target_effect_declarations: Path | str,
    transition_index_manifest: Path | str,
    mixed_original_plan: Path | str,
    writable_authority_report: Path | str,
    register_authority_report: Path | str,
    stack_dynamic_authority_report: Path | str,
    preservation_context: Path | str,
) -> GeneratedPreservationFrontier:
    """Derive GNU preservation inputs or emit the exact checked frontier.

    This production entry point never accepts a preassembled preservation
    family.  It may emit the final v1 inputs only after this module derives all
    target cases from checked semantics and the combined inventory.
    """

    _remove_stale_outputs(Path(out))
    paths = {
        "combined_inventory_manifest": Path(combined_inventory_manifest),
        "source_target_effect_declarations": Path(
            source_target_effect_declarations
        ),
        "transition_index_manifest": Path(transition_index_manifest),
        "mixed_original_plan": Path(mixed_original_plan),
        "writable_authority_report": Path(writable_authority_report),
        "register_authority_report": Path(register_authority_report),
        "stack_dynamic_authority_report": Path(stack_dynamic_authority_report),
        "preservation_context": Path(preservation_context),
    }
    documents = {name: _load(path, name) for name, path in paths.items()}
    hashes = {name: sha256_file(path) for name, path in paths.items()}

    combined = documents["combined_inventory_manifest"]
    effects = documents["source_target_effect_declarations"]
    transition = documents["transition_index_manifest"]
    context = documents["preservation_context"]
    _format(combined, _COMBINED_FORMAT, "combined inventory manifest")
    _format(effects, _EFFECTS_FORMAT, "source target-effect declarations")
    _format(transition, _TRANSITION_FORMAT, "transition-index manifest")
    _format(
        context,
        ORIGINAL_EXECUTION_PRESERVATION_CONTEXT_FORMAT,
        "preservation context",
    )

    _validate_context(context, hashes)
    targets = _targets(effects, transition)
    if len(targets) != _GNU_TARGET_COUNT:
        raise OriginalExecutionPreservationInputsError(
            f"GNU hello requires exactly {_GNU_TARGET_COUNT} reachable targets, "
            f"got {len(targets)}"
        )
    _validate_combined_bindings(combined, hashes)
    plan_target_ids = [
        _natural(value, "mixed plan reachable_target_ids[]")
        for value in _list(
            documents["mixed_original_plan"].get("reachable_target_ids"),
            "mixed plan reachable_target_ids",
        )
    ]
    target_ids = [target.target_id for target in targets]
    if plan_target_ids != target_ids:
        raise OriginalExecutionPreservationInputsError(
            "target-effect declarations differ from exact mixed-plan reachability"
        )
    counts = _object(combined.get("counts"), "combined inventory counts")
    expected_counts = {
        "reachable_targets": _GNU_TARGET_COUNT,
        "static_word_slots": _GNU_STATIC_WORD_COUNT,
        "register_requirements": _GNU_FRONTIER_COUNTS["register_target"],
        "stack_dynamic_requirements": _GNU_FRONTIER_COUNTS["stack_dynamic"],
    }
    for name, expected in expected_counts.items():
        if _natural(counts.get(name), f"combined counts.{name}") != expected:
            raise OriginalExecutionPreservationInputsError(
                f"combined inventory {name} does not equal {expected}"
            )
    transition_count = _natural(
        _object(transition.get("counts"), "transition counts").get("targets"),
        "transition counts.targets",
    )
    if transition_count != len(targets):
        raise OriginalExecutionPreservationInputsError(
            "transition-index and effect target counts differ"
        )

    transition_inputs = _object(transition.get("inputs"), "transition inputs")
    declaration_input = _object(
        transition_inputs.get("declaration_inventory"),
        "transition inputs.declaration_inventory",
    )
    if _digest(declaration_input.get("sha256"), "transition declaration hash") != hashes[
        "source_target_effect_declarations"
    ]:
        raise OriginalExecutionPreservationInputsError(
            "transition index does not bind the exact target-effect declarations"
        )

    combined_lean = _object(combined.get("lean"), "combined inventory lean")
    combined_module = _string(combined_lean.get("module"), "combined lean.module")
    inventory = _checked_ref_from_qualified(
        combined_module,
        _string(combined_lean.get("inventory"), "combined lean.inventory"),
        "combined lean.inventory",
    )
    original_context = _checked_ref_from_qualified(
        combined_module,
        _string(
            combined_lean.get("original_context"),
            "combined lean.original_context",
        ),
        "combined lean.original_context",
    )

    _validate_context_declarations(context)
    frontiers = _gnu_frontiers(documents, hashes)
    if len(frontiers) != sum(_GNU_FRONTIER_COUNTS.values()):
        raise OriginalExecutionPreservationInputsError(
            "GNU hello frontier inventory must contain exactly 31 sites"
        )

    missing = _derive_target_preservation_cases(targets, counts)
    if missing:
        return _write_preservation_frontier(
            out,
            context=context,
            hashes=hashes,
            targets=targets,
            frontiers=frontiers,
            combined_counts=counts,
            inventory=inventory,
            original_context=original_context,
            blockers=missing,
        )

    raise OriginalExecutionPreservationInputsError(
        "internal error: preservation closure reported complete without "
        "constructing a checked family"
    )


def _targets(
    effects: dict[str, Any], transition: dict[str, Any]
) -> tuple[PreservationTarget, ...]:
    namespace = _string(effects.get("namespace"), "effects.namespace")
    module_prefix = _string(effects.get("module_prefix"), "effects.module_prefix")
    shard_span = _positive(effects.get("shard_span"), "effects.shard_span")
    transition_modules = set(
        _string(value, "transition modules[]")
        for value in _list(transition.get("modules"), "transition modules")
    )
    rows = _list(effects.get("targets"), "effect targets")
    result: list[PreservationTarget] = []
    ids: list[int] = []
    for index, value in enumerate(rows):
        row = _object(value, f"effect targets[{index}]")
        target_id = _natural(row.get("target_id"), f"effect targets[{index}].target_id")
        kind = _string(row.get("kind"), f"effect targets[{index}].kind")
        evidence = _object(row.get("evidence"), f"effect targets[{index}].evidence")
        if kind == "ordinary":
            effect_refs = (
                _checked_ref(
                    evidence.get("checked_effect"),
                    f"effect targets[{index}].checked_effect",
                ),
            )
        elif kind == "x87":
            effect_refs = (
                _checked_ref(
                    evidence.get("facts"), f"effect targets[{index}].facts"
                ),
                _checked_ref(
                    evidence.get("successful_components"),
                    f"effect targets[{index}].successful_components",
                ),
            )
        else:
            raise OriginalExecutionPreservationInputsError(
                f"effect target {target_id} has unsupported kind {kind!r}"
            )
        shard_module = f"{module_prefix}Shard{target_id // shard_span:06d}"
        if shard_module not in transition_modules:
            raise OriginalExecutionPreservationInputsError(
                f"transition index omits shard {shard_module} for target {target_id}"
            )
        result.append(
            PreservationTarget(
                target_id=target_id,
                source_rva=_natural(
                    row.get("source_rva"),
                    f"effect targets[{index}].source_rva",
                    word=True,
                ),
                kind=kind,
                effect_refs=effect_refs,
                certificate=_checked_ref_from_qualified(
                    f"StageA.{shard_module}",
                    f"{namespace}.generatedActiveTargetTransitionCertificate_{target_id}",
                    f"target {target_id} transition certificate",
                ),
            )
        )
        ids.append(target_id)
    if ids != sorted(set(ids)):
        raise OriginalExecutionPreservationInputsError(
            "effect targets must be sorted and duplicate-free"
        )
    return tuple(result)


def _gnu_frontiers(
    documents: Mapping[str, dict[str, Any]], hashes: Mapping[str, str]
) -> tuple[PreservationFrontier, ...]:
    plan = documents["mixed_original_plan"]
    writable = documents["writable_authority_report"]
    register = documents["register_authority_report"]
    stack = documents["stack_dynamic_authority_report"]
    _format(plan, _MIXED_FORMAT, "mixed original plan")
    _format(writable, _WRITABLE_FORMAT, "writable authority report")
    _format(register, _REGISTER_FORMAT, "register authority report")
    _format(stack, _STACK_FORMAT, "stack authority report")
    _validate_report_bindings(plan, writable, register, stack, hashes)

    expected = _plan_frontiers(plan)
    result: list[PreservationFrontier] = []

    writable_rows = _list(writable.get("sites"), "writable sites")
    if len(writable_rows) != _GNU_FRONTIER_COUNTS["writable_static_slot"]:
        raise OriginalExecutionPreservationInputsError(
            "writable authority report must contain exactly 19 sites"
        )
    slot_rvas = sorted(
        {
            _natural(_object(row, "writable site").get("slot_rva"), "slot_rva")
            for row in writable_rows
        }
    )
    if len(slot_rvas) != _GNU_STATIC_WORD_COUNT:
        raise OriginalExecutionPreservationInputsError(
            "writable authorities must cover exactly three static words"
        )
    slot_indices = {rva: index for index, rva in enumerate(slot_rvas)}
    for index, value in enumerate(writable_rows):
        row = _object(value, f"writable sites[{index}]")
        result.append(
            PreservationFrontier(
                category="writable_static_slot",
                source_rva=_natural(row.get("source_rva"), "writable source_rva", word=True),
                source_target_id=_natural(row.get("source_target_id"), "writable source_target_id"),
                requirement_index=slot_indices[_natural(row.get("slot_rva"), "writable slot_rva")],
                static_authority=_lean_ref(
                    row.get("authorizing_lean_term"),
                    f"writable sites[{index}].authorizing_lean_term",
                ),
            )
        )

    register_rows = sorted(
        (_object(row, "register site") for row in _list(register.get("sites"), "register sites")),
        key=lambda row: _natural(row.get("source_rva"), "register source_rva"),
    )
    if len(register_rows) != _GNU_FRONTIER_COUNTS["register_target"]:
        raise OriginalExecutionPreservationInputsError(
            "register authority report must contain exactly nine sites"
        )
    if _list(register.get("blockers", []), "register blockers"):
        raise OriginalExecutionPreservationInputsError(
            "register authority report retains blockers"
        )
    for requirement_index, row in enumerate(register_rows):
        result.append(
            PreservationFrontier(
                category="register_target",
                source_rva=_natural(row.get("source_rva"), "register source_rva", word=True),
                source_target_id=_natural(row.get("source_target_id"), "register source_target_id"),
                requirement_index=requirement_index,
                static_authority=_lean_ref(
                    row.get("authorizing_lean_term"),
                    f"register sites[{requirement_index}].authorizing_lean_term",
                ),
            )
        )

    stack_rows = sorted(
        (_object(row, "stack site") for row in _list(stack.get("sites"), "stack sites")),
        key=lambda row: _natural(row.get("source_rva"), "stack source_rva"),
    )
    if len(stack_rows) != _GNU_FRONTIER_COUNTS["stack_dynamic"]:
        raise OriginalExecutionPreservationInputsError(
            "stack authority report must contain exactly three sites"
        )
    stack_symbols = {
        "finite_stack_target": "generatedOriginalStackDynamicClosure0StackAuthority",
        "empty_indexed_source": "generatedOriginalStackDynamicClosure1EmptyIndexedAuthority",
        "uninhabited_dynamic_source": "generatedOriginalStackDynamicClosure2SiteEvidence",
    }
    seen_modes: set[str] = set()
    for requirement_index, row in enumerate(stack_rows):
        mode = _string(row.get("closure_mode"), "stack closure_mode")
        if mode not in stack_symbols or mode in seen_modes:
            raise OriginalExecutionPreservationInputsError(
                "stack sites must contain each checked closure mode once"
            )
        if row.get("static_authority") != "lean_checked":
            raise OriginalExecutionPreservationInputsError(
                "stack site lacks Lean-checked static authority"
            )
        seen_modes.add(mode)
        result.append(
            PreservationFrontier(
                category="stack_dynamic",
                source_rva=_natural(row.get("source_rva"), "stack source_rva", word=True),
                source_target_id=_natural(row.get("source_target_id"), "stack source_target_id"),
                requirement_index=requirement_index,
                static_authority=_checked_ref_from_qualified(
                    "StageA.GeneratedRelationalOriginalStackDynamicControlClosure",
                    "StageA.GeneratedRelational.OriginalStackDynamicControlClosure."
                    + stack_symbols[mode],
                    f"stack sites[{requirement_index}].static_authority",
                ),
            )
        )

    keys = {(frontier.category, frontier.source_rva) for frontier in result}
    if keys != expected:
        missing = sorted(expected - keys)
        extra = sorted(keys - expected)
        raise OriginalExecutionPreservationInputsError(
            f"authority frontiers differ from mixed plan (missing={missing}, extra={extra})"
        )
    counts = {
        category: sum(frontier.category == category for frontier in result)
        for category in _GNU_FRONTIER_COUNTS
    }
    if counts != _GNU_FRONTIER_COUNTS:
        raise OriginalExecutionPreservationInputsError(
            f"frontier counts differ: {counts}"
        )
    return tuple(sorted(result, key=lambda frontier: (frontier.category, frontier.source_rva)))


def _plan_frontiers(plan: dict[str, Any]) -> set[tuple[str, int]]:
    result: set[tuple[str, int]] = set()
    for index, value in enumerate(_list(plan.get("blockers"), "mixed blockers")):
        row = _object(value, f"mixed blockers[{index}]")
        if row.get("reason_code") != "unresolved_indirect_control":
            raise OriginalExecutionPreservationInputsError(
                "mixed plan contains a non-indirect frontier"
            )
        detail = _string(row.get("detail"), "mixed blocker detail")
        if detail.startswith("static_pointer_slot at "):
            category = "writable_static_slot"
        elif detail.startswith(("register_function_pointer at ", "register_tail_target at ")):
            category = "register_target"
        elif detail.startswith("stack_or_dynamic_pointer at "):
            category = "stack_dynamic"
        else:
            raise OriginalExecutionPreservationInputsError(
                "mixed plan contains an unsupported frontier category"
            )
        key = (category, _natural(row.get("rva"), "mixed blocker rva", word=True))
        if key in result:
            raise OriginalExecutionPreservationInputsError(
                "mixed plan repeats an indirect frontier"
            )
        result.add(key)
    return result


def _validate_report_bindings(
    plan: dict[str, Any],
    writable: dict[str, Any],
    register: dict[str, Any],
    stack: dict[str, Any],
    hashes: Mapping[str, str],
) -> None:
    state_hash = _digest(plan.get("state_machine_sha256"), "plan state-machine hash")
    writable_inputs = _object(writable.get("inputs"), "writable inputs")
    register_inputs = _object(register.get("inputs"), "register inputs")
    stack_inputs = _object(stack.get("inputs"), "stack inputs")
    for label, inputs in (
        ("writable", writable_inputs),
        ("register", register_inputs),
    ):
        plan_hash = _digest(
            inputs.get("mixed_original_plan_sha256"), f"{label} plan hash"
        )
        if plan_hash != hashes["mixed_original_plan"]:
            raise OriginalExecutionPreservationInputsError(
                f"{label} report does not bind the exact mixed plan"
            )
        if _digest(inputs.get("state_machine_sha256"), f"{label} state hash") != state_hash:
            raise OriginalExecutionPreservationInputsError(
                f"{label} report does not bind the exact state machine"
            )
    if _digest(stack_inputs.get("state_machine_sha256"), "stack state hash") != state_hash:
        raise OriginalExecutionPreservationInputsError(
            "stack report does not bind the exact state machine"
        )
    original_hashes = {
        _digest(writable_inputs.get("original_sha256"), "writable original hash"),
        _digest(register_inputs.get("original_sha256"), "register original hash"),
        _digest(stack_inputs.get("original_pe_sha256"), "stack original hash"),
    }
    if len(original_hashes) != 1:
        raise OriginalExecutionPreservationInputsError(
            "frontier reports bind different original binaries"
        )


def _validate_combined_bindings(
    combined: dict[str, Any], hashes: Mapping[str, str]
) -> None:
    inputs = _object(combined.get("inputs"), "combined inventory inputs")
    for name in (
        "mixed_original_plan",
        "writable_authority_report",
        "register_authority_report",
        "stack_dynamic_authority_report",
    ):
        actual = _digest(
            inputs.get(name), f"combined inventory input {name}"
        )
        if actual != hashes[name]:
            raise OriginalExecutionPreservationInputsError(
                f"combined inventory does not bind exact {name}"
            )


def _validate_context(
    context: dict[str, Any], hashes: Mapping[str, str]
) -> None:
    expected = {
        "format",
        "namespace",
        "module_prefix",
        "shard_size",
        "inputs",
        "declarations",
    }
    _exact_keys(context, expected, "preservation context")
    namespace = _string(context.get("namespace"), "preservation context namespace")
    if _LEAN_NAMESPACE.fullmatch(namespace) is None:
        raise OriginalExecutionPreservationInputsError(
            "preservation context namespace must be canonical"
        )
    module_prefix = _string(
        context.get("module_prefix"), "preservation context module_prefix"
    )
    if _LEAN_LOCAL.fullmatch(module_prefix) is None:
        raise OriginalExecutionPreservationInputsError(
            "preservation context module_prefix must be a Lean identifier"
        )
    _positive(context.get("shard_size"), "preservation context shard_size")
    inputs = _object(context.get("inputs"), "preservation context inputs")
    expected_names = set(hashes) - {"preservation_context"}
    _exact_keys(inputs, expected_names, "preservation context inputs")
    for name in expected_names:
        if _digest(inputs[name], f"preservation context input {name}") != hashes[name]:
            raise OriginalExecutionPreservationInputsError(
                f"preservation context does not bind exact {name}"
            )


def _validate_context_declarations(context: dict[str, Any]) -> None:
    rows = _object(context.get("declarations"), "context declarations")
    expected = {
        "source_program",
        "target_ids_exact",
        "instruction_semantics_adequate",
        "protocol_responses",
        "project",
        "launch_inventory_holds",
        "launch_realizable",
        "compatibility_program_record_kernel_matches",
    }
    _exact_keys(rows, expected, "context declarations")
    for name in sorted(expected):
        _checked_ref(rows[name], f"context declarations.{name}")


def _derive_target_preservation_cases(
    targets: tuple[PreservationTarget, ...], combined_counts: Mapping[str, Any]
) -> list[dict[str, Any]]:
    """Return exact obligations not derivable from the current effect schema.

    A ``CheckedOriginalTargetEffect`` establishes exact successful target
    semantics.  It intentionally does not establish the structured control,
    memory, frame, value-flow, and indirect-target post evidence required by
    ``CheckedOriginalTargetPreservationCase``.  Until those checked witnesses
    are generated from the normalized effect data, closing the family would
    be unsound.
    """

    static_words = _natural(
        combined_counts.get("static_word_slots"),
        "combined counts.static_word_slots",
    )
    register_targets = _natural(
        combined_counts.get("register_requirements"),
        "combined counts.register_requirements",
    )
    stack_targets = _natural(
        combined_counts.get("stack_dynamic_requirements"),
        "combined counts.stack_dynamic_requirements",
    )
    call_frames = _natural(
        combined_counts.get("call_frame_facts", 0),
        "combined counts.call_frame_facts",
    )
    value_flows = _natural(
        combined_counts.get("value_flow_facts", 0),
        "combined counts.value_flow_facts",
    )
    missing_families = [
        "checked_effect_case",
        "normalized_transition",
        "reachability_post",
    ]
    if static_words:
        missing_families.append("static_word_post")
    if call_frames:
        missing_families.append("call_frame_post")
    if value_flows:
        missing_families.append("value_flow_post")
    if register_targets:
        missing_families.append("register_target_post")
    if stack_targets:
        missing_families.append("stack_dynamic_post")
    return [
        {
            "reason_code": "target_preservation_case_not_derivable",
            "target_id": target.target_id,
            "source_rva": target.source_rva,
            "effect_kind": target.kind,
            "checked_effects": [ref.to_json() for ref in target.effect_refs],
            "checked_transition_certificate": target.certificate.to_json(),
            "missing_checked_evidence": missing_families,
            "required_lean_type": "CheckedOriginalTargetPreservationCase",
        }
        for target in targets
    ]


def _write_preservation_frontier(
    out: Path | str,
    *,
    context: Mapping[str, Any],
    hashes: Mapping[str, str],
    targets: tuple[PreservationTarget, ...],
    frontiers: tuple[PreservationFrontier, ...],
    combined_counts: Mapping[str, Any],
    inventory: LeanRef,
    original_context: LeanRef,
    blockers: list[dict[str, Any]],
) -> GeneratedPreservationFrontier:
    root = Path(out)
    root.mkdir(parents=True, exist_ok=True)
    path = root / "original-execution-preservation-frontier.json"
    family_counts: dict[str, int] = {}
    for blocker in blockers:
        for family in blocker["missing_checked_evidence"]:
            family_counts[family] = family_counts.get(family, 0) + 1
    _write_json(
        path,
        {
            "format": ORIGINAL_EXECUTION_PRESERVATION_FRONTIER_FORMAT,
            "proof_authority": False,
            "acceptance_authority": False,
            "ready": False,
            "executes_original_binary": False,
            "executes_candidate_binary": False,
            "inputs": dict(sorted(hashes.items())),
            "requested_output_format": ORIGINAL_EXECUTION_PRESERVATION_INPUTS_FORMAT,
            "counts": {
                "reachable_targets": len(targets),
                "validated_frontiers": len(frontiers),
                "missing_target_cases": len(blockers),
                "missing_by_family": dict(sorted(family_counts.items())),
                "combined_inventory": {
                    name: combined_counts[name]
                    for name in sorted(combined_counts)
                },
            },
            "closure_boundary": {
                "namespace": context["namespace"],
                "module_prefix": context["module_prefix"],
                "combined_inventory": inventory.to_json(),
                "original_context": original_context.to_json(),
                "required_case_type": "CheckedOriginalTargetPreservationCase",
                "detail": (
                    "checked target effects and transition certificates do not "
                    "by themselves construct the structured post-state evidence"
                ),
                "next_action": (
                    "extend the generic preservation producer to derive each "
                    "listed post family from normalized effects and checked "
                    "inventory footprints"
                ),
            },
            "frontiers": [
                {
                    "category": frontier.category,
                    "source_rva": frontier.source_rva,
                    "source_target_id": frontier.source_target_id,
                    "requirement_index": frontier.requirement_index,
                    "static_authority": frontier.static_authority.to_json(),
                }
                for frontier in frontiers
            ],
            "blockers": blockers,
        },
    )
    return GeneratedPreservationFrontier(
        manifest=path,
        target_count=len(targets),
        frontier_count=len(frontiers),
        missing_target_cases=len(blockers),
    )


def _remove_stale_outputs(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    for name in (
        "original-execution-preservation-frontier.json",
        "original-execution-preservation-inputs.json",
        "original-execution-preservation-inputs-manifest.json",
    ):
        path = root / name
        if path.exists():
            path.unlink()


def _lean_ref(value: object, label: str) -> LeanRef:
    row = _object(value, label)
    if set(row) == {"module", "declaration"}:
        return _checked_ref(row, label)
    if set(row) == {"module", "namespace", "symbol"}:
        module = _string(row["module"], f"{label}.module")
        namespace = _string(row["namespace"], f"{label}.namespace")
        symbol = _string(row["symbol"], f"{label}.symbol")
        return _checked_ref_from_qualified(
            module, f"{namespace}.{symbol}", label
        )
    raise OriginalExecutionPreservationInputsError(
        f"{label} is not an exact Lean declaration reference"
    )


def _checked_ref(value: object, label: str) -> LeanRef:
    try:
        return LeanRef.from_json(value, label)
    except StageAInputError as error:
        raise OriginalExecutionPreservationInputsError(str(error)) from error


def _checked_ref_from_qualified(
    module: str, declaration: str, label: str
) -> LeanRef:
    try:
        return LeanRef.from_qualified(module, declaration)
    except StageAInputError as error:
        raise OriginalExecutionPreservationInputsError(
            f"{label} is not a canonical Lean declaration: {error}"
        ) from error


def _load(path: Path, label: str) -> dict[str, Any]:
    try:
        return _object(json.loads(path.read_text(encoding="utf-8")), label)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise OriginalExecutionPreservationInputsError(
            f"cannot read {label}: {error}"
        ) from error


def _write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="ascii"
    )


def _format(document: Mapping[str, Any], expected: str, label: str) -> None:
    if document.get("format") != expected:
        raise OriginalExecutionPreservationInputsError(
            f"{label} has unsupported format"
        )


def _object(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise OriginalExecutionPreservationInputsError(f"{label} must be an object")
    return value


def _list(value: object, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise OriginalExecutionPreservationInputsError(f"{label} must be a list")
    return value


def _string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise OriginalExecutionPreservationInputsError(
            f"{label} must be a non-empty string"
        )
    return value


def _natural(value: object, label: str, *, word: bool = False) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise OriginalExecutionPreservationInputsError(
            f"{label} must be a natural number"
        )
    if word and value > 0xFFFFFFFF:
        raise OriginalExecutionPreservationInputsError(
            f"{label} must fit in a 32-bit word"
        )
    return value


def _positive(value: object, label: str) -> int:
    result = _natural(value, label)
    if result == 0:
        raise OriginalExecutionPreservationInputsError(f"{label} must be positive")
    return result


def _digest(value: object, label: str) -> str:
    result = _string(value, label)
    if _SHA256.fullmatch(result) is None:
        raise OriginalExecutionPreservationInputsError(
            f"{label} must be a SHA-256 digest"
        )
    return result


def _exact_keys(row: Mapping[str, Any], expected: set[str], label: str) -> None:
    actual = set(row)
    if actual != expected:
        raise OriginalExecutionPreservationInputsError(
            f"{label} fields differ (missing={sorted(expected - actual)}, "
            f"unexpected={sorted(actual - expected)})"
        )


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--combined-inventory-manifest", required=True)
    parser.add_argument("--source-target-effect-declarations", required=True)
    parser.add_argument("--transition-index-manifest", required=True)
    parser.add_argument("--mixed-original-plan", required=True)
    parser.add_argument("--writable-authority-report", required=True)
    parser.add_argument("--register-authority-report", required=True)
    parser.add_argument("--stack-dynamic-authority-report", required=True)
    parser.add_argument("--preservation-context", required=True)
    parser.add_argument("--out", required=True)
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    generate_gnu_hello_original_execution_preservation_inputs(
        args.out,
        combined_inventory_manifest=args.combined_inventory_manifest,
        source_target_effect_declarations=args.source_target_effect_declarations,
        transition_index_manifest=args.transition_index_manifest,
        mixed_original_plan=args.mixed_original_plan,
        writable_authority_report=args.writable_authority_report,
        register_authority_report=args.register_authority_report,
        stack_dynamic_authority_report=args.stack_dynamic_authority_report,
        preservation_context=args.preservation_context,
    )


if __name__ == "__main__":
    main()


__all__ = [
    "ORIGINAL_EXECUTION_PRESERVATION_CONTEXT_FORMAT",
    "ORIGINAL_EXECUTION_PRESERVATION_FRONTIER_FORMAT",
    "GeneratedPreservationFrontier",
    "OriginalExecutionPreservationInputsError",
    "PreservationFrontier",
    "PreservationTarget",
    "generate_gnu_hello_original_execution_preservation_inputs",
]

from __future__ import annotations

import json
from typing import Any, Mapping, Sequence

from ..stage_binary import StageABinary
from .analyses.register_lattice import RegisterRelation, _REGISTER_RELATION_KINDS
from .analyses.register_static import (
    _immutable_image_word_read,
    _paired_constant_relation,
)
from .analyses.segments import _semantic_expr_registers
from .contract import _semantic_expr_is_pure
from .extraction import _semantic_exact_memory_inputs
from .register_transfer_core import (
    REGISTER_ORDER,
    REGISTER_TRANSFER_CONTEXT_FORMAT,
    REGISTER_TRANSFER_PROGRAM_FORMAT,
    REGISTER_TRANSFER_PROGRAMS_FORMAT,
    RegisterTransferIncomplete,
    RegisterTransferResult,
    canonical_sha256,
    evaluate_register_transfer_program,
    fixed_expression_supported,
    parse_register_transfer_context,
    parse_register_transfer_program,
    parse_register_transfer_programs,
    register_transfer_programs_payload,
    relation_json,
)


def _matching_static_word_relation_slot(
    original_expression: dict[str, Any],
    candidate_expression: dict[str, Any],
    contract: Mapping[str, Any],
) -> dict[str, Any] | None:
    from .analyses.control import _constant_read32_address

    original_address = _constant_read32_address(original_expression)
    candidate_address = _constant_read32_address(candidate_expression)
    if original_address is None or candidate_address is None:
        return None
    code_targets = contract.get("code_targets", [])
    matches = []
    for slot in contract.get("static_word_relation_slots", []):
        if not isinstance(slot, dict):
            continue
        relation = str(slot.get("relation"))
        target_id = slot.get("target_id")
        valid_fixed_target = (
            relation == "fixed_code_pointer"
            and isinstance(target_id, int)
            and not isinstance(target_id, bool)
            and target_id >= 0
            and isinstance(code_targets, list)
            and target_id < len(code_targets)
            and isinstance(code_targets[target_id], dict)
            and code_targets[target_id].get("id") == target_id
        )
        if (
            int(slot.get("original_address", -1)) == original_address
            and int(slot.get("candidate_address", -1)) == candidate_address
            and (
                relation in _REGISTER_RELATION_KINDS - {"fixed_code_pointer"}
                or valid_fixed_target
            )
        ):
            matches.append(slot)
    return dict(matches[0]) if len(matches) == 1 else None


def _side_context(binary: StageABinary) -> dict[str, Any]:
    ranges = []
    candidates = [(0, binary.size_of_headers)] + [
        (section.rva_start, section.rva_end - section.rva_start)
        for section in binary.sections
        if not section.writable
    ]
    for rva, size in sorted(set(candidates)):
        raw = binary.pe.get_data(rva, size)
        if raw:
            ranges.append({
                "start": binary.image_base + rva,
                "bytes_hex": raw.hex(),
            })
    forbidden = sorted({
        (
            binary.image_base + int(imported.thunk_rva),
            binary.image_base + int(imported.thunk_rva) + 4,
        )
        for imported in binary.imports
        if imported.thunk_rva is not None
    })
    return {
        "sha256": binary.sha256,
        "image_base": binary.image_base,
        "immutable_ranges": ranges,
        "forbidden_ranges": [
            {"start": start, "end": end} for start, end in forbidden
        ],
    }


def register_transfer_context_payload(
    *,
    contract: Mapping[str, Any],
    original_bin: StageABinary,
    candidate_bin: StageABinary,
) -> dict[str, Any]:
    value_targets = sorted(
        {
            (
                int(target["original_value"]) & 0xFFFFFFFF,
                int(target["candidate_value"]) & 0xFFFFFFFF,
            )
            for target in contract.get("value_targets", [])
        }
    )
    code_targets = []
    for target_id, target in enumerate(contract.get("code_targets", [])):
        canonical = isinstance(target, dict) and target.get("id") == target_id
        original_rvas = (
            [target.get("original_rva", -1), *target.get("original_aliases", [])]
            if canonical else []
        )
        candidate_rvas = (
            [target.get("candidate_rva", -1), *target.get("candidate_aliases", [])]
            if canonical else []
        )
        code_targets.append({
            "id": target_id,
            "original_values": sorted({
                (original_bin.image_base + int(rva)) & 0xFFFFFFFF
                for rva in original_rvas
            }),
            "candidate_values": sorted({
                (candidate_bin.image_base + int(rva)) & 0xFFFFFFFF
                for rva in candidate_rvas
            }),
        })
    body = {
        "format": REGISTER_TRANSFER_CONTEXT_FORMAT,
        "status": "untrusted_proposal_requires_lean_replay",
        "acceptance_authority": False,
        "original": _side_context(original_bin),
        "candidate": _side_context(candidate_bin),
        "value_targets": [
            {"original_value": original, "candidate_value": candidate}
            for original, candidate in value_targets
        ],
        "code_targets": code_targets,
    }
    payload = {**body, "context_sha256": canonical_sha256(body)}
    parse_register_transfer_context(payload)
    return payload


def _compile_output_rules(
    *,
    original_expression: dict[str, Any],
    candidate_expression: dict[str, Any],
    input_pairs: Mapping[str, str],
    contract: Mapping[str, Any],
    original_image_base: int,
    candidate_image_base: int,
    original_bin: StageABinary | None,
    candidate_bin: StageABinary | None,
) -> tuple[list[dict[str, Any]], bool]:
    constant_relation = _paired_constant_relation(
        original_expression,
        candidate_expression,
        dict(contract),
        original_image_base,
        candidate_image_base,
    )
    if constant_relation is not None:
        return [{
            "op": "emit",
            "relation": relation_json(constant_relation),
            "reason": "paired_constant",
        }], False
    static_slot = _matching_static_word_relation_slot(
        original_expression, candidate_expression, contract,
    )
    if static_slot is not None:
        relation: RegisterRelation = str(static_slot["relation"])
        if relation == "fixed_code_pointer":
            relation = {
                "relation": "fixed_code_pointer",
                "target_id": int(static_slot["target_id"]),
            }
        return [{
            "op": "emit",
            "relation": relation_json(relation),
            "reason": "static_word_slot",
        }], False
    if original_bin is not None and candidate_bin is not None:
        original_read = _immutable_image_word_read(
            original_expression, original_bin,
        )
        candidate_read = _immutable_image_word_read(
            candidate_expression, candidate_bin,
        )
        if original_read is not None and candidate_read is not None:
            _, original_writes, original_assembled, original_value = original_read
            _, candidate_writes, candidate_assembled, candidate_value = candidate_read
            immutable_relation = _paired_constant_relation(
                {"op": "constant", "value": original_value},
                {"op": "constant", "value": candidate_value},
                dict(contract),
                original_image_base,
                candidate_image_base,
            )
            if immutable_relation is not None:
                reason = None
                if not original_assembled and not candidate_assembled:
                    reason = "immutable_image_word"
                elif (
                    original_assembled == candidate_assembled
                    and len(original_writes) == len(candidate_writes)
                ):
                    reason = "assembled_immutable_image_word"
                if reason is not None:
                    return [{
                        "op": "emit",
                        "relation": relation_json(immutable_relation),
                        "reason": reason,
                    }], False
    if (
        original_expression.get("op") == "input_reg"
        and candidate_expression.get("op") == "input_reg"
    ):
        source = str(original_expression.get("reg"))
        if str(candidate_expression.get("reg")) == input_pairs.get(source, source):
            return [{
                "op": "copy_input",
                "source_register": source,
                "reason": "identity_transfer",
            }], False

    rules: list[dict[str, Any]] = []
    dynamic = (
        original_bin is not None
        and candidate_bin is not None
        and fixed_expression_supported(original_expression)
        and fixed_expression_supported(candidate_expression)
    )
    if dynamic:
        rules.append({
            "op": "fixed_expression",
            "original_expression": json.loads(json.dumps(original_expression)),
            "candidate_expression": json.loads(json.dumps(candidate_expression)),
            "reason": "fixed_immutable_expression",
        })
    if original_expression == candidate_expression:
        dependencies = sorted(_semantic_expr_registers(original_expression))
        if _semantic_expr_is_pure(original_expression):
            rules.append({
                "op": "exact_if_inputs_exact",
                "dependencies": dependencies,
                "reason": "lean_exact_memory_free_expression",
            })
        if (
            not contract.get("value_targets")
            and _semantic_exact_memory_inputs(
                original_expression, set(REGISTER_ORDER),
            )
        ):
            rules.append({
                "op": "exact_if_inputs_exact",
                "dependencies": dependencies,
                "reason": "lean_exact_memory_expression",
            })
    rules.append({
        "op": "emit",
        "relation": "related_word",
        "reason": "unsupported_or_mixed_relation",
    })
    return rules, dynamic


def compile_register_transfer_program(
    *,
    region_id: str,
    behavior_pair: Mapping[str, Any],
    input_pairs: Mapping[str, str],
    output_pairs: Mapping[str, str],
    contract: Mapping[str, Any],
    original_image_base: int,
    candidate_image_base: int,
    original_bin: StageABinary | None,
    candidate_bin: StageABinary | None,
    context_sha256: str | None = None,
    register_order: Sequence[str] = REGISTER_ORDER,
) -> dict[str, Any]:
    original_registers = behavior_pair["original_ir"]["registers"]
    candidate_registers = behavior_pair["candidate_ir"]["registers"]
    outputs = []
    uses_dynamic = False
    for register in register_order:
        candidate_register = output_pairs.get(register)
        if (
            register not in original_registers
            or candidate_register is None
            or candidate_register not in candidate_registers
        ):
            rules = [{
                "op": "emit",
                "relation": "related_word",
                "reason": "output_register_pair_missing",
            }]
        else:
            rules, output_dynamic = _compile_output_rules(
                original_expression=original_registers[register],
                candidate_expression=candidate_registers[candidate_register],
                input_pairs=input_pairs,
                contract=contract,
                original_image_base=original_image_base,
                candidate_image_base=candidate_image_base,
                original_bin=original_bin,
                candidate_bin=candidate_bin,
            )
            uses_dynamic |= output_dynamic
        outputs.append({
            "register": register,
            "candidate_register": candidate_register,
            "rules": rules,
        })
    if uses_dynamic and context_sha256 is None:
        # In-memory unit fixtures may use binary stubs. Serialized Stage A
        # artifacts are rejected by the strict parser until context is bound.
        dependency = None
    else:
        dependency = context_sha256 if uses_dynamic else None
    body = {
        "format": REGISTER_TRANSFER_PROGRAM_FORMAT,
        "region_id": str(region_id),
        "input_pairs": [
            {
                "original": register,
                "candidate": input_pairs.get(register, register),
            }
            for register in register_order
        ],
        "context_sha256": dependency,
        "outputs": outputs,
    }
    return {**body, "program_sha256": canonical_sha256(body)}


__all__ = [
    "REGISTER_ORDER",
    "REGISTER_TRANSFER_CONTEXT_FORMAT",
    "REGISTER_TRANSFER_PROGRAM_FORMAT",
    "REGISTER_TRANSFER_PROGRAMS_FORMAT",
    "RegisterTransferIncomplete",
    "RegisterTransferResult",
    "compile_register_transfer_program",
    "evaluate_register_transfer_program",
    "parse_register_transfer_context",
    "parse_register_transfer_program",
    "parse_register_transfer_programs",
    "register_transfer_context_payload",
    "register_transfer_programs_payload",
]

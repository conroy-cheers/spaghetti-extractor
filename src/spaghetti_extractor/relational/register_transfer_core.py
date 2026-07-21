from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from ..errors import StageAInputError
from .analyses.register_lattice import (
    RegisterRelation,
    _REGISTER_RELATION_KINDS,
    _register_relation_implies_exact,
    _register_relation_payload,
)
from .schema import STAGE_A_RELATIONAL_MODEL_ID, STAGE_A_RELATIONAL_PROFILE_ID


REGISTER_ORDER = ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
REGISTER_TRANSFER_PROGRAM_FORMAT = "stage-a-register-transfer-program-v1"
REGISTER_TRANSFER_PROGRAMS_FORMAT = "stage-a-register-transfer-programs-v1"
REGISTER_TRANSFER_CONTEXT_FORMAT = "stage-a-register-transfer-context-v1"
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_FIXED_BINARY_OPERATIONS = frozenset({
    "add",
    "sub",
    "bit_and",
    "bit_xor",
    "bit_or",
    "multiply",
    "multiply_high_unsigned",
    "multiply_high_signed",
    "shift_left_by",
    "shift_right_by",
    "shift_arithmetic_right_by",
    "unsigned_less_value",
})
_FIXED_UNARY_OPERATIONS = frozenset({
    "bit_not", "lowest_set_bit", "highest_set_bit",
})


class RegisterTransferIncomplete(Exception):
    """A transfer program cannot be evaluated from its declared evidence."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class RegisterTransferResult:
    relations: dict[str, RegisterRelation]
    reasons: dict[str, str]


def canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def _relation_without_register(
    value: object, context: str,
) -> RegisterRelation:
    if isinstance(value, str):
        if value not in _REGISTER_RELATION_KINDS:
            raise StageAInputError(f"{context} has unsupported relation kind")
        if value in {"fixed_word", "fixed_code_pointer"}:
            raise StageAInputError(f"{context} is missing relation payload")
        return value
    if not isinstance(value, dict):
        raise StageAInputError(f"{context} must be a relation")
    kind = value.get("relation")
    if (
        kind in _REGISTER_RELATION_KINDS - {"fixed_word", "fixed_code_pointer"}
        and set(value) == {"relation"}
    ):
        return str(kind)
    if kind == "fixed_word":
        if set(value) != {"relation", "value"} or not (
            isinstance(value["value"], int)
            and not isinstance(value["value"], bool)
            and 0 <= value["value"] < 2**32
        ):
            raise StageAInputError(f"{context} has invalid fixed word")
        return {"relation": "fixed_word", "value": int(value["value"])}
    if kind == "fixed_code_pointer":
        if set(value) != {"relation", "target_id"} or not (
            isinstance(value["target_id"], int)
            and not isinstance(value["target_id"], bool)
            and value["target_id"] >= 0
        ):
            raise StageAInputError(f"{context} has invalid fixed code target")
        return {
            "relation": "fixed_code_pointer",
            "target_id": int(value["target_id"]),
        }
    raise StageAInputError(f"{context} has unsupported relation payload")


def relation_json(relation: RegisterRelation) -> str | dict[str, Any]:
    return dict(relation) if isinstance(relation, dict) else relation


def fixed_register_values(
    input_relations: Mapping[str, RegisterRelation],
    candidate_registers: Mapping[str, str] | None,
) -> tuple[dict[str, int], dict[str, int]]:
    original_values: dict[str, int] = {}
    candidate_rows: dict[str, list[int]] = {}
    for original_register, relation in input_relations.items():
        payload = _register_relation_payload(relation)
        if payload["relation"] != "fixed_word":
            continue
        value = int(payload["value"]) & 0xFFFFFFFF
        original_values[str(original_register)] = value
        candidate_register = str(
            (candidate_registers or {}).get(
                str(original_register), str(original_register),
            )
        )
        candidate_rows.setdefault(candidate_register, []).append(value)
    candidate_values = {
        register: values[0]
        for register, values in candidate_rows.items()
        if len(values) == 1
    }
    return original_values, candidate_values


def fixed_expression_supported(expression: Any) -> bool:
    if not isinstance(expression, dict):
        return False
    operation = expression.get("op")
    if operation == "input_reg":
        return isinstance(expression.get("reg"), str)
    if operation == "constant":
        return (
            isinstance(expression.get("value"), int)
            and not isinstance(expression.get("value"), bool)
        )
    if operation in _FIXED_BINARY_OPERATIONS:
        return all(
            fixed_expression_supported(expression.get(field))
            for field in ("left", "right")
        )
    if operation in _FIXED_UNARY_OPERATIONS:
        return fixed_expression_supported(expression.get("value"))
    if operation in {"shift_left", "shift_right"}:
        return (
            fixed_expression_supported(expression.get("value"))
            and isinstance(expression.get("amount"), int)
            and not isinstance(expression.get("amount"), bool)
            and int(expression["amount"]) >= 0
        )
    if operation in {"extract_byte", "bit_value"}:
        return (
            fixed_expression_supported(expression.get("value"))
            and isinstance(expression.get("index"), int)
            and not isinstance(expression.get("index"), bool)
            and int(expression["index"]) >= 0
        )
    if operation in {"read8", "read32"}:
        return fixed_expression_supported(expression.get("address"))
    if operation == "if_equal":
        return all(
            fixed_expression_supported(expression.get(field))
            for field in ("left", "right", "then", "else")
        )
    return False


def expression_reads_immutable_memory(expression: Any) -> bool:
    if not isinstance(expression, dict):
        return False
    if expression.get("op") in {"read8", "read32"}:
        return True
    return any(
        expression_reads_immutable_memory(value)
        for key, value in expression.items()
        if key != "op" and isinstance(value, dict)
    )


def _context_side(payload: object, context: str) -> dict[str, Any]:
    if not isinstance(payload, dict) or set(payload) != {
        "sha256", "image_base", "immutable_ranges", "forbidden_ranges",
    }:
        raise StageAInputError(f"{context} fields do not match")
    if not isinstance(payload["sha256"], str) or _SHA256_RE.fullmatch(
        payload["sha256"]
    ) is None:
        raise StageAInputError(f"{context}.sha256 is invalid")
    if not (
        isinstance(payload["image_base"], int)
        and not isinstance(payload["image_base"], bool)
        and 0 <= payload["image_base"] < 2**32
    ):
        raise StageAInputError(f"{context}.image_base is invalid")
    ranges = payload["immutable_ranges"]
    if not isinstance(ranges, list):
        raise StageAInputError(f"{context}.immutable_ranges must be a list")
    previous_end = -1
    normalized_ranges = []
    for index, item in enumerate(ranges):
        if not isinstance(item, dict) or set(item) != {"start", "bytes_hex"}:
            raise StageAInputError(f"{context} range {index} is invalid")
        start = item["start"]
        encoded = item["bytes_hex"]
        if not (
            isinstance(start, int)
            and not isinstance(start, bool)
            and 0 <= start < 2**32
            and isinstance(encoded, str)
            and len(encoded) % 2 == 0
        ):
            raise StageAInputError(f"{context} range {index} is invalid")
        try:
            raw = bytes.fromhex(encoded)
        except ValueError as exc:
            raise StageAInputError(
                f"{context} range {index} bytes are invalid"
            ) from exc
        end = start + len(raw)
        if not raw or end > 2**32 or start < previous_end:
            raise StageAInputError(f"{context} ranges overlap or are empty")
        previous_end = end
        normalized_ranges.append({
            "start": start, "end": end, "bytes": raw, "bytes_hex": encoded,
        })
    forbidden = payload["forbidden_ranges"]
    if not isinstance(forbidden, list):
        raise StageAInputError(f"{context}.forbidden_ranges must be a list")
    normalized_forbidden = []
    prior = (-1, -1)
    for index, item in enumerate(forbidden):
        if not isinstance(item, dict) or set(item) != {"start", "end"}:
            raise StageAInputError(f"{context} forbidden range is invalid")
        start, end = item["start"], item["end"]
        if not (
            isinstance(start, int)
            and not isinstance(start, bool)
            and isinstance(end, int)
            and not isinstance(end, bool)
            and 0 <= start < end <= 2**32
            and (start, end) > prior
        ):
            raise StageAInputError(f"{context} forbidden range is invalid")
        prior = (start, end)
        normalized_forbidden.append({"start": start, "end": end})
    return {
        "sha256": payload["sha256"],
        "image_base": payload["image_base"],
        "immutable_ranges": normalized_ranges,
        "forbidden_ranges": normalized_forbidden,
    }


def parse_register_transfer_context(payload: object) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise StageAInputError("register transfer context must be an object")
    expected_fields = {
        "format", "status", "acceptance_authority", "original", "candidate",
        "value_targets", "code_targets", "context_sha256",
    }
    if set(payload) != expected_fields:
        raise StageAInputError("register transfer context fields do not match")
    body = {key: value for key, value in payload.items() if key != "context_sha256"}
    if (
        payload["format"] != REGISTER_TRANSFER_CONTEXT_FORMAT
        or payload["status"] != "untrusted_proposal_requires_lean_replay"
        or payload["acceptance_authority"] is not False
    ):
        raise StageAInputError("register transfer context identity is invalid")
    if payload["context_sha256"] != canonical_sha256(body):
        raise StageAInputError("register transfer context digest does not match")
    original = _context_side(payload["original"], "original transfer context")
    candidate = _context_side(payload["candidate"], "candidate transfer context")
    value_targets = payload["value_targets"]
    if not isinstance(value_targets, list):
        raise StageAInputError("register transfer value targets must be a list")
    normalized_values = []
    for item in value_targets:
        if not isinstance(item, dict) or set(item) != {
            "original_value", "candidate_value",
        }:
            raise StageAInputError("register transfer value target is invalid")
        if any(
            not isinstance(item[field], int)
            or isinstance(item[field], bool)
            or not 0 <= item[field] < 2**32
            for field in item
        ):
            raise StageAInputError("register transfer value target is invalid")
        normalized_values.append(dict(item))
    code_targets = payload["code_targets"]
    if not isinstance(code_targets, list):
        raise StageAInputError("register transfer code targets must be a list")
    normalized_code = []
    for index, item in enumerate(code_targets):
        if not isinstance(item, dict) or set(item) != {
            "id", "original_values", "candidate_values",
        }:
            raise StageAInputError("register transfer code target is invalid")
        if item["id"] != index:
            raise StageAInputError("register transfer code targets are not canonical")
        for field in ("original_values", "candidate_values"):
            values = item[field]
            if (
                not isinstance(values, list)
                or values != sorted(set(values))
                or any(
                    not isinstance(value, int)
                    or isinstance(value, bool)
                    or not 0 <= value < 2**32
                    for value in values
                )
            ):
                raise StageAInputError("register transfer code values are invalid")
        normalized_code.append(dict(item))
    return {
        **json.loads(json.dumps(payload)),
        "original": original,
        "candidate": candidate,
        "value_targets": normalized_values,
        "code_targets": normalized_code,
    }


def _immutable_u32(context: Mapping[str, Any], side: str, address: int) -> int | None:
    side_context = context[side]
    if any(
        int(item["start"]) < address + 4 and address < int(item["end"])
        for item in side_context["forbidden_ranges"]
    ):
        return None
    matches = [
        item for item in side_context["immutable_ranges"]
        if int(item["start"]) <= address
        and address + 4 <= int(item["end"])
    ]
    if len(matches) != 1:
        return None
    item = matches[0]
    raw = item.get("bytes")
    if not isinstance(raw, bytes):
        raw = bytes.fromhex(str(item["bytes_hex"]))
    offset = address - int(item["start"])
    return int.from_bytes(raw[offset:offset + 4], "little")


def fixed_expression_value(
    expression: Any,
    fixed_registers: Mapping[str, int],
    *,
    context: Mapping[str, Any],
    side: str,
) -> int | None:
    if not isinstance(expression, dict):
        return None
    operation = str(expression.get("op", ""))
    mask = 0xFFFFFFFF
    if operation == "input_reg":
        value = fixed_registers.get(str(expression.get("reg", "")))
        return None if value is None else value & mask
    if operation == "constant":
        value = expression.get("value")
        if not isinstance(value, int) or isinstance(value, bool):
            return None
        return value & mask
    if operation in _FIXED_BINARY_OPERATIONS:
        left = fixed_expression_value(
            expression.get("left"), fixed_registers, context=context, side=side,
        )
        right = fixed_expression_value(
            expression.get("right"), fixed_registers, context=context, side=side,
        )
        if left is None or right is None:
            return None
        if operation == "add":
            return (left + right) & mask
        if operation == "sub":
            return (left - right) & mask
        if operation == "bit_and":
            return left & right
        if operation == "bit_xor":
            return left ^ right
        if operation == "bit_or":
            return left | right
        if operation == "multiply":
            return (left * right) & mask
        if operation == "multiply_high_unsigned":
            return ((left * right) >> 32) & mask
        if operation == "multiply_high_signed":
            signed_left = left if left < 0x80000000 else left - 0x100000000
            signed_right = right if right < 0x80000000 else right - 0x100000000
            return ((signed_left * signed_right) >> 32) & mask
        if operation == "shift_left_by":
            return (left << (right % 32)) & mask
        if operation == "shift_right_by":
            return left >> (right % 32)
        if operation == "shift_arithmetic_right_by":
            signed = left if left < 0x80000000 else left - 0x100000000
            return (signed >> (right % 32)) & mask
        return 1 if left < right else 0
    if operation in _FIXED_UNARY_OPERATIONS:
        value = fixed_expression_value(
            expression.get("value"), fixed_registers, context=context, side=side,
        )
        if value is None:
            return None
        if operation == "bit_not":
            return (~value) & mask
        if operation == "lowest_set_bit":
            return 32 if value == 0 else (value & -value).bit_length() - 1
        return 0 if value == 0 else value.bit_length() - 1
    if operation in {"shift_left", "shift_right"}:
        value = fixed_expression_value(
            expression.get("value"), fixed_registers, context=context, side=side,
        )
        amount = expression.get("amount")
        if (
            value is None
            or not isinstance(amount, int)
            or isinstance(amount, bool)
            or amount < 0
        ):
            return None
        if operation == "shift_left":
            return (value << amount) & mask if amount < 32 else 0
        return value >> amount if amount < 32 else 0
    if operation in {"extract_byte", "bit_value"}:
        value = fixed_expression_value(
            expression.get("value"), fixed_registers, context=context, side=side,
        )
        index = expression.get("index")
        if (
            value is None
            or not isinstance(index, int)
            or isinstance(index, bool)
            or index < 0
        ):
            return None
        if operation == "extract_byte":
            return (value >> (index * 8)) & 0xFF if index < 4 else 0
        return (value >> index) & 1 if index < 32 else 0
    if operation in {"read8", "read32"}:
        address = fixed_expression_value(
            expression.get("address"), fixed_registers, context=context, side=side,
        )
        if address is None:
            return None
        word = _immutable_u32(context, side, address)
        if word is None:
            return None
        return word & 0xFF if operation == "read8" else word
    if operation == "if_equal":
        left = fixed_expression_value(
            expression.get("left"), fixed_registers, context=context, side=side,
        )
        right = fixed_expression_value(
            expression.get("right"), fixed_registers, context=context, side=side,
        )
        if left is None or right is None:
            return None
        return fixed_expression_value(
            expression.get("then" if left == right else "else"),
            fixed_registers,
            context=context,
            side=side,
        )
    return None


def _paired_constant_relation(
    original_value: int,
    candidate_value: int,
    context: Mapping[str, Any],
) -> RegisterRelation | None:
    original_value &= 0xFFFFFFFF
    candidate_value &= 0xFFFFFFFF
    if original_value == candidate_value:
        return {"relation": "fixed_word", "value": original_value}
    if any(
        item["original_value"] == original_value
        and item["candidate_value"] == candidate_value
        for item in context["value_targets"]
    ):
        return "data_pointer"
    matches = [
        int(item["id"])
        for item in context["code_targets"]
        if original_value in item["original_values"]
        and candidate_value in item["candidate_values"]
    ]
    if len(matches) == 1:
        return {"relation": "fixed_code_pointer", "target_id": matches[0]}
    if matches:
        return "code_pointer"
    return None


def parse_register_transfer_program(payload: object) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise StageAInputError("register transfer program must be an object")
    expected_fields = {
        "format", "region_id", "input_pairs", "context_sha256", "outputs",
        "program_sha256",
    }
    if set(payload) != expected_fields:
        raise StageAInputError("register transfer program fields do not match")
    body = {key: value for key, value in payload.items() if key != "program_sha256"}
    if payload["format"] != REGISTER_TRANSFER_PROGRAM_FORMAT:
        raise StageAInputError("register transfer program format is invalid")
    if not isinstance(payload["region_id"], str) or not payload["region_id"]:
        raise StageAInputError("register transfer program region ID is invalid")
    if payload["program_sha256"] != canonical_sha256(body):
        raise StageAInputError("register transfer program digest does not match")
    context_sha256 = payload["context_sha256"]
    if context_sha256 is not None and (
        not isinstance(context_sha256, str)
        or _SHA256_RE.fullmatch(context_sha256) is None
    ):
        raise StageAInputError("register transfer program context is invalid")
    input_pairs = payload["input_pairs"]
    if not isinstance(input_pairs, list) or len(input_pairs) != len(REGISTER_ORDER):
        raise StageAInputError("register transfer input pairs are invalid")
    for index, pair in enumerate(input_pairs):
        if not isinstance(pair, dict) or set(pair) != {"original", "candidate"}:
            raise StageAInputError("register transfer input pair is invalid")
        if pair["original"] != REGISTER_ORDER[index]:
            raise StageAInputError("register transfer input pairs are not canonical")
        if not isinstance(pair["candidate"], str) or not pair["candidate"]:
            raise StageAInputError("register transfer candidate input is invalid")
    outputs = payload["outputs"]
    if not isinstance(outputs, list) or len(outputs) != len(REGISTER_ORDER):
        raise StageAInputError("register transfer outputs are invalid")
    dynamic_rule_count = 0
    for output_index, output in enumerate(outputs):
        output_context = f"register transfer output {output_index}"
        if not isinstance(output, dict) or set(output) != {
            "register", "candidate_register", "rules",
        }:
            raise StageAInputError(f"{output_context} fields do not match")
        if output["register"] != REGISTER_ORDER[output_index]:
            raise StageAInputError("register transfer outputs are not canonical")
        if output["candidate_register"] is not None and not isinstance(
            output["candidate_register"], str
        ):
            raise StageAInputError(
                f"{output_context} candidate register is invalid"
            )
        rules = output["rules"]
        if not isinstance(rules, list) or not rules:
            raise StageAInputError(f"{output_context} rules are empty")
        if rules[-1].get("op") not in {"emit", "copy_input"}:
            raise StageAInputError(f"{output_context} has no total terminal rule")
        for rule_index, rule in enumerate(rules):
            rule_context = f"{output_context} rule {rule_index}"
            if not isinstance(rule, dict):
                raise StageAInputError(f"{rule_context} must be an object")
            operation = rule.get("op")
            if operation == "emit":
                if set(rule) != {"op", "relation", "reason"}:
                    raise StageAInputError(f"{rule_context} fields do not match")
                _relation_without_register(rule["relation"], rule_context)
            elif operation == "copy_input":
                if set(rule) != {"op", "source_register", "reason"}:
                    raise StageAInputError(f"{rule_context} fields do not match")
                if rule["source_register"] not in REGISTER_ORDER:
                    raise StageAInputError(f"{rule_context} source is invalid")
            elif operation == "fixed_expression":
                if set(rule) != {
                    "op", "original_expression", "candidate_expression", "reason",
                }:
                    raise StageAInputError(f"{rule_context} fields do not match")
                if not all(
                    fixed_expression_supported(rule[field])
                    for field in ("original_expression", "candidate_expression")
                ):
                    raise StageAInputError(
                        f"{rule_context} expression is unsupported"
                    )
                dynamic_rule_count += 1
            elif operation == "exact_if_inputs_exact":
                if set(rule) != {"op", "dependencies", "reason"}:
                    raise StageAInputError(f"{rule_context} fields do not match")
                dependencies = rule["dependencies"]
                if (
                    not isinstance(dependencies, list)
                    or dependencies != sorted(set(dependencies))
                    or any(item not in REGISTER_ORDER for item in dependencies)
                ):
                    raise StageAInputError(
                        f"{rule_context} dependencies are invalid"
                    )
            else:
                raise StageAInputError(f"{rule_context} operation is unsupported")
            if not isinstance(rule.get("reason"), str) or not rule["reason"]:
                raise StageAInputError(f"{rule_context} reason is invalid")
    if (dynamic_rule_count > 0) != (context_sha256 is not None):
        raise StageAInputError(
            "register transfer context dependency does not match its rules"
        )
    return json.loads(json.dumps(payload))


def _parse_relation_row(value: object, context: str) -> dict[str, Any]:
    if not isinstance(value, dict) or "register" not in value:
        raise StageAInputError(f"{context} must be a register relation")
    register = value["register"]
    if register not in REGISTER_ORDER:
        raise StageAInputError(f"{context} register is invalid")
    relation = _relation_without_register(
        {key: item for key, item in value.items() if key != "register"},
        context,
    )
    return {"register": register, **_register_relation_payload(relation)}


def _parse_propagation(
    payload: object, program_ids: Sequence[str],
) -> dict[str, Any]:
    if not isinstance(payload, dict) or set(payload) != {"regions", "edges"}:
        raise StageAInputError("register transfer propagation fields do not match")
    raw_regions = payload["regions"]
    if not isinstance(raw_regions, list):
        raise StageAInputError("register propagation regions must be a list")
    regions = []
    for index, item in enumerate(raw_regions):
        if not isinstance(item, dict) or set(item) != {
            "id", "seed_relation", "stack_window_registers",
        }:
            raise StageAInputError("register propagation region is malformed")
        seed = item["seed_relation"]
        if seed not in {None, "exact", "related_word"}:
            raise StageAInputError("register propagation seed is unsupported")
        stack = item["stack_window_registers"]
        if (
            not isinstance(stack, list)
            or stack != sorted(set(stack))
            or any(register not in REGISTER_ORDER for register in stack)
        ):
            raise StageAInputError("register propagation stack inventory is invalid")
        regions.append({
            "id": item["id"],
            "seed_relation": seed,
            "stack_window_registers": stack,
        })
    if [item["id"] for item in regions] != list(program_ids):
        raise StageAInputError(
            "register propagation region inventory does not match programs"
        )
    raw_edges = payload["edges"]
    if not isinstance(raw_edges, list):
        raise StageAInputError("register propagation edges must be a list")
    valid_ids = set(program_ids)
    edges = []
    seen: set[str] = set()
    for index, item in enumerate(raw_edges):
        if not isinstance(item, dict) or set(item) != {
            "source_id", "target_id", "environment_barrier", "kind",
            "preserved_registers", "result_relations",
        }:
            raise StageAInputError("register propagation edge is malformed")
        if item["source_id"] not in valid_ids or item["target_id"] not in valid_ids:
            raise StageAInputError("register propagation edge target is unknown")
        if not isinstance(item["environment_barrier"], bool):
            raise StageAInputError("register propagation barrier is invalid")
        if not isinstance(item["kind"], str) or not item["kind"]:
            raise StageAInputError("register propagation edge kind is invalid")
        preserved = item["preserved_registers"]
        if (
            not isinstance(preserved, list)
            or preserved != sorted(set(preserved))
            or any(register not in REGISTER_ORDER for register in preserved)
        ):
            raise StageAInputError("register propagation preserved set is invalid")
        raw_results = item["result_relations"]
        if not isinstance(raw_results, list):
            raise StageAInputError("register propagation results must be a list")
        results = [
            _parse_relation_row(result, f"propagation edge {index} result {offset}")
            for offset, result in enumerate(raw_results)
        ]
        if [result["register"] for result in results] != sorted(
            {result["register"] for result in results}, key=REGISTER_ORDER.index,
        ):
            raise StageAInputError("register propagation results are not canonical")
        normalized = {
            "source_id": item["source_id"],
            "target_id": item["target_id"],
            "environment_barrier": item["environment_barrier"],
            "kind": item["kind"],
            "preserved_registers": preserved,
            "result_relations": results,
        }
        key = json.dumps(normalized, sort_keys=True, separators=(",", ":"))
        if key in seen:
            raise StageAInputError("register propagation edges are duplicated")
        seen.add(key)
        edges.append(normalized)
    expected_edges = sorted(
        edges,
        key=lambda edge: (
            edge["target_id"], edge["source_id"], edge["kind"],
            json.dumps(edge, sort_keys=True, separators=(",", ":")),
        ),
    )
    if edges != expected_edges:
        raise StageAInputError("register propagation edges are not canonical")
    return {"regions": regions, "edges": edges}


def register_transfer_programs_payload(
    *,
    original_sha256: str,
    candidate_sha256: str,
    graph_sha256: str,
    context: Mapping[str, Any],
    programs: Sequence[Mapping[str, Any]],
    propagation: Mapping[str, Any],
) -> dict[str, Any]:
    parsed_context = parse_register_transfer_context(context)
    body = {
        "format": REGISTER_TRANSFER_PROGRAMS_FORMAT,
        "profile": STAGE_A_RELATIONAL_PROFILE_ID,
        "model": STAGE_A_RELATIONAL_MODEL_ID,
        "status": "untrusted_proposal_requires_lean_replay",
        "acceptance_authority": False,
        "original_sha256": original_sha256,
        "candidate_sha256": candidate_sha256,
        "graph_sha256": graph_sha256,
        "region_count": len(programs),
        "context": {
            key: value for key, value in parsed_context.items()
            if key not in {"original", "candidate"}
        } | {
            "original": context["original"],
            "candidate": context["candidate"],
        },
        "programs": [dict(program) for program in programs],
        "propagation": dict(propagation),
    }
    payload = {**body, "artifact_sha256": canonical_sha256(body)}
    parse_register_transfer_programs(
        payload,
        expected_original_sha256=original_sha256,
        expected_candidate_sha256=candidate_sha256,
        expected_graph_sha256=graph_sha256,
    )
    return payload


def parse_register_transfer_programs(
    payload: object,
    *,
    expected_original_sha256: str,
    expected_candidate_sha256: str,
    expected_graph_sha256: str,
) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise StageAInputError("register transfer programs must be an object")
    expected_fields = {
        "format", "profile", "model", "status", "acceptance_authority",
        "original_sha256", "candidate_sha256", "graph_sha256", "region_count",
        "context", "programs", "propagation", "artifact_sha256",
    }
    if set(payload) != expected_fields:
        raise StageAInputError("register transfer programs fields do not match")
    body = {key: value for key, value in payload.items() if key != "artifact_sha256"}
    expected_identity = {
        "format": REGISTER_TRANSFER_PROGRAMS_FORMAT,
        "profile": STAGE_A_RELATIONAL_PROFILE_ID,
        "model": STAGE_A_RELATIONAL_MODEL_ID,
        "status": "untrusted_proposal_requires_lean_replay",
        "acceptance_authority": False,
        "original_sha256": expected_original_sha256,
        "candidate_sha256": expected_candidate_sha256,
        "graph_sha256": expected_graph_sha256,
    }
    for field, expected in expected_identity.items():
        if payload.get(field) != expected:
            raise StageAInputError(
                f"register transfer programs {field} does not match"
            )
    for field in ("original_sha256", "candidate_sha256", "graph_sha256"):
        if not isinstance(payload[field], str) or _SHA256_RE.fullmatch(
            payload[field]
        ) is None:
            raise StageAInputError(
                f"register transfer programs {field} is invalid"
            )
    if payload["artifact_sha256"] != canonical_sha256(body):
        raise StageAInputError("register transfer programs digest does not match")
    context = parse_register_transfer_context(payload["context"])
    if (
        context["original"]["sha256"] != expected_original_sha256
        or context["candidate"]["sha256"] != expected_candidate_sha256
    ):
        raise StageAInputError("register transfer context binary does not match")
    raw_programs = payload["programs"]
    if (
        not isinstance(raw_programs, list)
        or payload["region_count"] != len(raw_programs)
    ):
        raise StageAInputError("register transfer program count does not match")
    programs = tuple(parse_register_transfer_program(item) for item in raw_programs)
    ids = [program["region_id"] for program in programs]
    if len(ids) != len(set(ids)):
        raise StageAInputError("register transfer program IDs are ambiguous")
    if any(
        program["context_sha256"] is not None
        and program["context_sha256"] != context["context_sha256"]
        for program in programs
    ):
        raise StageAInputError("register transfer program context does not match")
    propagation = _parse_propagation(payload["propagation"], ids)
    return {
        "context": json.loads(json.dumps(payload["context"])),
        "programs": programs,
        "propagation": propagation,
    }


def evaluate_register_transfer_program(
    program_payload: object,
    input_relations: Mapping[str, RegisterRelation],
    *,
    context_payload: object,
    validate: bool = True,
    validate_context: bool = True,
) -> RegisterTransferResult:
    program = (
        parse_register_transfer_program(program_payload)
        if validate else dict(program_payload)  # type: ignore[arg-type]
    )
    if set(input_relations) != set(REGISTER_ORDER):
        raise RegisterTransferIncomplete("input_register_inventory_incomplete")
    if context_payload is None:
        raise RegisterTransferIncomplete("transfer_context_missing")
    context = (
        parse_register_transfer_context(context_payload)
        if validate_context else context_payload
    )
    if not isinstance(context, Mapping):
        raise RegisterTransferIncomplete("transfer_context_invalid")
    if (
        program["context_sha256"] is not None
        and program["context_sha256"] != context["context_sha256"]
    ):
        raise RegisterTransferIncomplete("transfer_context_identity_mismatch")
    input_pairs = {
        str(pair["original"]): str(pair["candidate"])
        for pair in program["input_pairs"]
    }
    original_fixed, candidate_fixed = fixed_register_values(
        input_relations, input_pairs,
    )
    relations: dict[str, RegisterRelation] = {}
    reasons: dict[str, str] = {}
    for output in program["outputs"]:
        register = str(output["register"])
        selected: RegisterRelation | None = None
        selected_reason: str | None = None
        for rule in output["rules"]:
            operation = rule["op"]
            if operation == "emit":
                selected = _relation_without_register(
                    rule["relation"], f"transfer {register}",
                )
                selected_reason = str(rule["reason"])
                break
            if operation == "copy_input":
                selected = input_relations.get(
                    str(rule["source_register"]), "related_word",
                )
                selected_reason = str(rule["reason"])
                break
            if operation == "fixed_expression":
                original_value = fixed_expression_value(
                    rule["original_expression"],
                    original_fixed,
                    context=context,
                    side="original",
                )
                candidate_value = fixed_expression_value(
                    rule["candidate_expression"],
                    candidate_fixed,
                    context=context,
                    side="candidate",
                )
                if original_value is None or candidate_value is None:
                    continue
                selected = _paired_constant_relation(
                    original_value, candidate_value, context,
                )
                if selected is not None:
                    selected_reason = str(rule["reason"])
                    break
                continue
            if operation == "exact_if_inputs_exact":
                if all(
                    _register_relation_implies_exact(
                        input_relations.get(dependency, "related_word")
                    )
                    for dependency in rule["dependencies"]
                ):
                    selected = "exact"
                    selected_reason = str(rule["reason"])
                    break
                continue
            raise RegisterTransferIncomplete("transfer_operation_unsupported")
        if selected is None or selected_reason is None:
            raise RegisterTransferIncomplete("transfer_program_not_total")
        relations[register] = selected
        reasons[register] = selected_reason
    return RegisterTransferResult(relations=relations, reasons=reasons)


__all__ = [
    "REGISTER_ORDER",
    "REGISTER_TRANSFER_CONTEXT_FORMAT",
    "REGISTER_TRANSFER_PROGRAM_FORMAT",
    "REGISTER_TRANSFER_PROGRAMS_FORMAT",
    "RegisterTransferIncomplete",
    "RegisterTransferResult",
    "canonical_sha256",
    "evaluate_register_transfer_program",
    "expression_reads_immutable_memory",
    "fixed_expression_supported",
    "fixed_expression_value",
    "fixed_register_values",
    "parse_register_transfer_context",
    "parse_register_transfer_program",
    "parse_register_transfer_programs",
    "register_transfer_programs_payload",
    "relation_json",
]

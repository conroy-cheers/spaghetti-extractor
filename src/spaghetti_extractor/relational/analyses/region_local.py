from __future__ import annotations

import json
from typing import Any

from ...stage_binary import StageABinary
from ..contract import _import_identity, _semantic_expr_is_pure
from ..extraction import (
    _assembled_u32_after_register_writes,
    _unique_import_at_absolute_address,
)
from ..model import _semantic_hash
from .control import _constant_read32_address
from .register_static import (
    _immutable_image_word_read,
    _paired_constant_relation,
)
from .segments import _semantic_expr_registers


def _semantic_index_from_address(
    address: dict[str, Any], base: int, element_size: int,
) -> dict[str, Any] | None:
    if address.get("op") != "add":
        return None
    for constant_side, scaled_side in (("left", "right"), ("right", "left")):
        constant = address.get(constant_side)
        scaled = address.get(scaled_side)
        if not isinstance(constant, dict) or constant.get("op") != "constant":
            continue
        offset = (int(constant["value"]) - base) & 0xFFFFFFFF
        if offset >= element_size or not isinstance(scaled, dict):
            continue
        if element_size == 1:
            return scaled
        if element_size & (element_size - 1) == 0:
            shift = element_size.bit_length() - 1
            if (
                scaled.get("op") == "shift_left"
                and int(scaled.get("amount", -1)) == shift
            ):
                return scaled.get("value")
        if scaled.get("op") == "multiply":
            for factor, value in (
                (scaled.get("left"), scaled.get("right")),
                (scaled.get("right"), scaled.get("left")),
            ):
                if (
                    isinstance(factor, dict)
                    and factor.get("op") == "constant"
                    and int(factor["value"]) == element_size
                    and isinstance(value, dict)
                ):
                    return value
    return None


def _semantic_read_addresses(value: Any) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    if isinstance(value, dict):
        if value.get("op") in {"read8", "read32"} and isinstance(
            value.get("address"), dict
        ):
            result.append(value["address"])
        for key, child in value.items():
            if key != "op":
                result.extend(_semantic_read_addresses(child))
    elif isinstance(value, list):
        for child in value:
            result.extend(_semantic_read_addresses(child))
    return result


def _exact_index_expression(
    region: dict[str, Any],
    behavior: dict[str, Any],
    bound: dict[str, Any],
    side: str,
) -> dict[str, Any] | None:
    upper = int(bound["unsigned_lt"])
    register = str(bound[side])
    matches: dict[str, dict[str, Any]] = {}
    for target in region.get("values", []):
        mapped_size = int(target.get("mapped_size", 0))
        if upper <= 0 or mapped_size <= 0 or mapped_size % upper != 0:
            continue
        element_size = mapped_size // upper
        if element_size not in {1, 2, 4, 8}:
            continue
        base = int(target[f"{side}_value"])
        for address in _semantic_read_addresses(behavior):
            expression = _semantic_index_from_address(address, base, element_size)
            if (
                expression is not None
                and (
                    register in _semantic_expr_registers(expression)
                    or (behavior.get("registers") or {}).get(register) == expression
                )
                and _semantic_expr_is_pure(expression)
            ):
                matches[_semantic_hash(expression)] = expression
    if len(matches) != 1:
        return None
    return next(iter(matches.values()))


def _stack_index_expression(
    region: dict[str, Any],
    behavior: dict[str, Any],
    bound: dict[str, Any],
    side: str,
) -> dict[str, Any] | None:
    """Find a table index loaded into the bounded register from one stack word.

    This is only a request for later stack-window validation.  In particular,
    finding the table and its decoded index does not establish the runtime
    bound and must not make the table candidate usable by itself.
    """
    upper = bound.get("unsigned_lt")
    register = bound.get(side)
    if (
        not isinstance(upper, int)
        or isinstance(upper, bool)
        or upper <= 0
        or not isinstance(register, str)
    ):
        return None
    register_output = (behavior.get("registers") or {}).get(register)
    if not isinstance(register_output, dict) or register_output.get("op") != "read32":
        return None
    matches: dict[str, dict[str, Any]] = {}
    for target in region.get("values", []):
        mapped_size = int(target.get("mapped_size", 0))
        if mapped_size <= 0 or mapped_size % upper != 0:
            continue
        element_size = mapped_size // upper
        if element_size not in {1, 2, 4, 8}:
            continue
        base = int(target[f"{side}_value"])
        for address in _semantic_read_addresses(behavior):
            expression = _semantic_index_from_address(address, base, element_size)
            if expression == register_output:
                matches[_semantic_hash(expression)] = expression
    if len(matches) != 1:
        return None
    return next(iter(matches.values()))


def _refine_contract_bounds(
    contract: dict[str, Any], behaviors: list[dict[str, Any]],
) -> dict[str, Any]:
    refined = json.loads(json.dumps(contract))
    for region, behavior_pair in zip(refined["regions"], behaviors, strict=True):
        for bound in region.get("bounds", []):
            bound.pop("stack_bound_request", None)
            found = True
            for side in ("original", "candidate"):
                expression = _exact_index_expression(
                    region, behavior_pair[f"{side}_ir"], bound, side
                )
                if expression is None:
                    found = False
                    break
                bound[f"{side}_expression"] = expression
            if found:
                bound["expression_source"] = "lean_exact_effective_address"
            else:
                bound.pop("original_expression", None)
                bound.pop("candidate_expression", None)
                bound.pop("expression_source", None)
                stack_expressions = {
                    side: _stack_index_expression(
                        region, behavior_pair[f"{side}_ir"], bound, side
                    )
                    for side in ("original", "candidate")
                }
                if all(stack_expressions.values()):
                    bound["stack_bound_request"] = {
                        "profile": "decoded_stack_register_bound_request_v1",
                        "original_expression": stack_expressions["original"],
                        "candidate_expression": stack_expressions["candidate"],
                    }
    return refined


def _iat_seed_read(
    expression: dict[str, Any],
) -> tuple[int, list[dict[str, Any]], bool] | None:
    direct = _constant_read32_address(expression)
    if direct is not None:
        return direct, [], False
    assembled = _assembled_u32_after_register_writes(expression)
    if assembled is None:
        return None
    address, writes = assembled
    return address, writes, True


def _iat_import_register_seed_candidates(
    original_bin: StageABinary,
    candidate_bin: StageABinary,
    behaviors: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for region_index, behavior_pair in enumerate(behaviors):
        original_registers = behavior_pair["original_ir"].get("registers") or {}
        candidate_registers = behavior_pair["candidate_ir"].get("registers") or {}
        for original_register, original_expression in sorted(
            original_registers.items()
        ):
            original_read = _iat_seed_read(original_expression)
            if original_read is None:
                continue
            original_address, original_writes, original_assembled = original_read
            original_import = _unique_import_at_absolute_address(
                original_bin, original_address
            )
            original_identity = (
                _import_identity(original_import)
                if original_import is not None else None
            )
            if original_identity is None:
                continue
            matches: list[dict[str, Any]] = []
            for candidate_register, candidate_expression in sorted(
                candidate_registers.items()
            ):
                candidate_read = _iat_seed_read(candidate_expression)
                if candidate_read is None:
                    continue
                candidate_address, candidate_writes, candidate_assembled = (
                    candidate_read
                )
                candidate_import = _unique_import_at_absolute_address(
                    candidate_bin, candidate_address
                )
                if (
                    candidate_import is None
                    or _import_identity(candidate_import) != original_identity
                    or candidate_assembled != original_assembled
                    or len(candidate_writes) != len(original_writes)
                ):
                    continue
                matches.append({
                    "profile": (
                        "assembled_iat_register_seed_v1"
                        if original_assembled else "iat_register_seed_v1"
                    ),
                    "region_index": region_index,
                    "original_register": original_register,
                    "candidate_register": candidate_register,
                    "original_iat_rva": int(original_import.thunk_rva),
                    "candidate_iat_rva": int(candidate_import.thunk_rva),
                    "original_absolute_address": original_address,
                    "candidate_absolute_address": candidate_address,
                    "assembled_read": original_assembled,
                    "original_writes": original_writes,
                    "candidate_writes": candidate_writes,
                    "import": {
                        "dll": original_identity[0],
                        original_identity[1]: original_identity[2],
                    },
                })
            if len(matches) == 1:
                result.append(matches[0])
    return result


def _attach_import_seed_address_separations(
    contract: dict[str, Any], seeds: list[dict[str, Any]],
) -> dict[str, Any]:
    refined = json.loads(json.dumps(contract))
    regions = refined.get("regions", [])
    for seed in seeds:
        if not seed.get("assembled_read"):
            continue
        original_writes = seed.get("original_writes", [])
        candidate_writes = seed.get("candidate_writes", [])
        if len(original_writes) != len(candidate_writes):
            continue
        region_index = int(seed["region_index"])
        if not 0 <= region_index < len(regions):
            continue
        rows = regions[region_index].setdefault("address_separations", [])
        keys = {
            (
                str(row["original_register"]),
                str(row["candidate_register"]),
                int(row["original_offset"]),
                int(row["candidate_offset"]),
                int(row["original_address"]),
                int(row["candidate_address"]),
            )
            for row in rows
        }
        for original_write, candidate_write in zip(
            original_writes, candidate_writes, strict=True
        ):
            for word_byte in range(4):
                for write_byte in range(4):
                    key = (
                        str(original_write["register"]),
                        str(candidate_write["register"]),
                        (int(original_write["offset"]) + write_byte) & 0xFFFFFFFF,
                        (int(candidate_write["offset"]) + write_byte) & 0xFFFFFFFF,
                        (int(seed["original_absolute_address"]) + word_byte)
                        & 0xFFFFFFFF,
                        (int(seed["candidate_absolute_address"]) + word_byte)
                        & 0xFFFFFFFF,
                    )
                    if key in keys:
                        continue
                    rows.append({
                        "original_register": key[0],
                        "candidate_register": key[1],
                        "original_offset": key[2],
                        "candidate_offset": key[3],
                        "original_address": key[4],
                        "candidate_address": key[5],
                        "source": "assembled_iat_write_separation",
                    })
                    keys.add(key)
        rows.sort(key=lambda row: (
            str(row["original_register"]),
            str(row["candidate_register"]),
            int(row["original_offset"]),
            int(row["candidate_offset"]),
            int(row["original_address"]),
            int(row["candidate_address"]),
        ))
    return refined


def _attach_assembled_immutable_read_address_separations(
    contract: dict[str, Any],
    behaviors: list[dict[str, Any]],
    original_bin: StageABinary,
    candidate_bin: StageABinary,
) -> dict[str, Any]:
    refined = json.loads(json.dumps(contract))
    regions = refined.get("regions", [])
    if len(regions) != len(behaviors):
        return refined
    for region, behavior_pair in zip(regions, behaviors, strict=True):
        original_registers = behavior_pair["original_ir"].get("registers") or {}
        candidate_registers = behavior_pair["candidate_ir"].get("registers") or {}
        read_pairs: list[
            tuple[int, list[dict[str, Any]], int, list[dict[str, Any]]]
        ] = []
        for pair in region.get("outputs", []):
            original_expression = original_registers.get(str(pair.get("original")))
            candidate_expression = candidate_registers.get(str(pair.get("candidate")))
            if not isinstance(original_expression, dict) or not isinstance(
                candidate_expression, dict
            ):
                continue
            original_read = _immutable_image_word_read(
                original_expression, original_bin
            )
            candidate_read = _immutable_image_word_read(
                candidate_expression, candidate_bin
            )
            if original_read is None or candidate_read is None:
                continue
            (
                original_address,
                original_writes,
                original_assembled,
                original_value,
            ) = original_read
            (
                candidate_address,
                candidate_writes,
                candidate_assembled,
                candidate_value,
            ) = candidate_read
            if (
                not original_assembled
                or not candidate_assembled
                or len(original_writes) != len(candidate_writes)
                or _paired_constant_relation(
                    {"op": "constant", "value": original_value},
                    {"op": "constant", "value": candidate_value},
                    refined,
                    original_bin.image_base,
                    candidate_bin.image_base,
                ) is None
            ):
                continue
            read_pairs.append((
                original_address,
                original_writes,
                candidate_address,
                candidate_writes,
            ))
        original_outcome = behavior_pair["original_ir"].get("outcome") or {}
        candidate_outcome = behavior_pair["candidate_ir"].get("outcome") or {}
        if (
            original_outcome.get("op") in {"indirect_call", "indirect_jump"}
            and candidate_outcome.get("op") == original_outcome.get("op")
        ):
            original_read = _immutable_image_word_read(
                original_outcome.get("target") or {}, original_bin
            )
            candidate_read = _immutable_image_word_read(
                candidate_outcome.get("target") or {}, candidate_bin
            )
            if original_read is not None and candidate_read is not None:
                (
                    original_address,
                    original_writes,
                    original_assembled,
                    original_value,
                ) = original_read
                (
                    candidate_address,
                    candidate_writes,
                    candidate_assembled,
                    candidate_value,
                ) = candidate_read
                if (
                    original_assembled
                    and candidate_assembled
                    and len(original_writes) == len(candidate_writes)
                    and _paired_constant_relation(
                        {"op": "constant", "value": original_value},
                        {"op": "constant", "value": candidate_value},
                        refined,
                        original_bin.image_base,
                        candidate_bin.image_base,
                    ) is not None
                ):
                    read_pairs.append((
                        original_address,
                        original_writes,
                        candidate_address,
                        candidate_writes,
                    ))
        if not read_pairs:
            continue
        rows = region.setdefault("address_separations", [])
        keys = {
            (
                str(row["original_register"]),
                str(row["candidate_register"]),
                int(row["original_offset"]),
                int(row["candidate_offset"]),
                int(row["original_address"]),
                int(row["candidate_address"]),
            )
            for row in rows
        }
        for (
            original_address,
            original_writes,
            candidate_address,
            candidate_writes,
        ) in read_pairs:
            for original_write, candidate_write in zip(
                original_writes, candidate_writes, strict=True
            ):
                for word_byte in range(4):
                    for write_byte in range(4):
                        key = (
                            str(original_write["register"]),
                            str(candidate_write["register"]),
                            (int(original_write["offset"]) + write_byte)
                            & 0xFFFFFFFF,
                            (int(candidate_write["offset"]) + write_byte)
                            & 0xFFFFFFFF,
                            (original_address + word_byte) & 0xFFFFFFFF,
                            (candidate_address + word_byte) & 0xFFFFFFFF,
                        )
                        if key in keys:
                            continue
                        rows.append({
                            "original_register": key[0],
                            "candidate_register": key[1],
                            "original_offset": key[2],
                            "candidate_offset": key[3],
                            "original_address": key[4],
                            "candidate_address": key[5],
                            "source": (
                                "assembled_immutable_word_write_separation"
                            ),
                        })
                        keys.add(key)
        rows.sort(key=lambda row: (
            str(row["original_register"]),
            str(row["candidate_register"]),
            int(row["original_offset"]),
            int(row["candidate_offset"]),
            int(row["original_address"]),
            int(row["candidate_address"]),
        ))
    return refined


__all__ = [
    "_attach_assembled_immutable_read_address_separations",
    "_attach_import_seed_address_separations",
    "_exact_index_expression",
    "_iat_import_register_seed_candidates",
    "_refine_contract_bounds",
    "_semantic_index_from_address",
    "_semantic_read_addresses",
]

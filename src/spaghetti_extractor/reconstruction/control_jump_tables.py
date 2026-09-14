"""Static PE32 jump-table recognition and recovery."""

from __future__ import annotations

import copy
from hashlib import sha256
from typing import Any, Callable, Iterable, Mapping, Sequence

from .control_common import (
    _binary_operands,
    _canonical_json,
    _canonical_mapping_key,
    _constant_value,
    _index_register,
    _instruction_immediate,
    _instruction_register,
    _is_u32,
    _same_expression,
)


RvaReader = Callable[[int, int], bytes]
_UNSIGNED_LESS_OPS = frozenset(
    {"unsigned_less", "unsigned_lt", "ult", "ult32"}
)
_UNSIGNED_LESS_EQUAL_OPS = frozenset(
    {"unsigned_less_equal", "unsigned_le", "ule", "ule32"}
)


def pe32_jump_table_index_expression(
    target_expression: Mapping[str, Any],
) -> dict[str, Any] | None:
    """Return the exact index expression from a supported PE32 table load."""

    shape = _indexed_load_shape(target_expression)
    return copy.deepcopy(dict(shape[1])) if shape is not None else None


def recover_static_pe32_jump_table_inventory(
    *,
    target_expression: Mapping[str, Any],
    predecessor_evidence: Sequence[Mapping[str, Any]],
    image_base: int,
    sections: Sequence[Mapping[str, Any] | Any],
    read_rva: RvaReader,
    finite_index_domain: Mapping[str, Any] | None = None,
    valid_target_rvas: Iterable[int] | None = None,
    max_entries: int = 4096,
) -> dict[str, Any]:
    """Recover one immutable PE32 absolute-pointer jump-table inventory.

    Supported target expressions are a 32-bit load from ``base + index * 4``;
    multiplication by four and a left shift by two are treated identically.
    The index domain may come from bounded machine-IR dataflow. Otherwise every
    incoming predecessor must establish the same unsigned upper bound. Wrapped
    or sparse domains are read entry-by-entry instead of widening their span.

    Analysis failures are data, not exceptions: an incomplete result has an
    empty target inventory and a stable failure code.  Invalid API parameters
    such as a non-positive resolver cap still raise ``ValueError``.
    """

    if max_entries <= 0:
        raise ValueError("max_entries must be positive")
    kind = "pe32_indexed_absolute_jump_table"
    if not _is_u32(image_base):
        return _table_failure(kind, "invalid_image_base", "image_base is not a PE32 value")

    shape = _indexed_load_shape(target_expression)
    if shape is None:
        return _table_failure(
            kind,
            "unsupported_target_expression",
            "target expression is not an exact 32-bit base + index * 4 load",
        )
    table_address, index_expression, expression_form = shape

    remap_shape = _immutable_byte_remap_shape(index_expression)
    bound_expression = (
        remap_shape[1] if remap_shape is not None else index_expression
    )
    evidence_rows: list[dict[str, Any]] = []
    index_values: list[int] | None = None
    dataflow_evidence: dict[str, Any] | None = None
    if (
        remap_shape is None
        and isinstance(finite_index_domain, Mapping)
        and finite_index_domain.get("status") == "complete"
    ):
        expected_expression_sha256 = sha256(
            _canonical_json(index_expression).encode("utf-8")
        ).hexdigest()
        raw_values = finite_index_domain.get("values")
        if (
            finite_index_domain.get("format")
            != "spaghetti-extractor-finite-u32-expression-domain-v1"
            or finite_index_domain.get("expression_sha256")
            != expected_expression_sha256
            or not isinstance(raw_values, list)
            or any(not _is_u32(value) for value in raw_values)
        ):
            return _table_failure(
                kind,
                "invalid_finite_index_domain",
                (
                    "finite index-domain evidence is malformed or bound to "
                    "another expression"
                ),
            )
        index_values = sorted({int(value) for value in raw_values})
        if not index_values or len(index_values) > max_entries:
            return _table_failure(
                kind,
                "invalid_index_bound",
                "finite index domain is empty or exceeds the resolver cap",
            )
        dataflow_evidence = copy.deepcopy(dict(finite_index_domain))
        evidence_rows.append({
            "source_unit_id": str(
                finite_index_domain.get("source_unit_id", "finite-u32-dataflow")
            ),
            "values": index_values,
            "sources": ["finite_u32_dataflow"],
        })

    source_upper_exclusive: int | None = None
    if index_values is None:
        bounds: set[int] = set()
        if not predecessor_evidence:
            return _table_failure(
                kind,
                "missing_predecessor_evidence",
                "no predecessor proves a finite index bound",
            )
        for ordinal, row in enumerate(
            sorted(predecessor_evidence, key=_canonical_mapping_key)
        ):
            if not isinstance(row, Mapping):
                return _table_failure(
                    kind,
                    "invalid_predecessor_evidence",
                    "predecessor evidence contains a non-mapping row",
                )
            guard = _predecessor_path_guard(row)
            predecessor_index = _predecessor_output_expression(
                row, bound_expression
            )
            guard_bound = (
                _guard_upper_exclusive(guard, predecessor_index)
                if guard is not None
                else None
            )
            instruction_bound = _instruction_upper_exclusive(row, bound_expression)
            row_bounds = {
                value
                for value in (guard_bound, instruction_bound)
                if value is not None
            }
            if len(row_bounds) > 1:
                return _table_failure(
                    kind,
                    "ambiguous_index_bound",
                    "guard and instruction evidence disagree on the index bound",
                )
            if not row_bounds:
                return _table_failure(
                    kind,
                    "unresolved_index_bound",
                    (
                        "an incoming predecessor does not prove a supported "
                        "unsigned bound"
                    ),
                )
            upper = next(iter(row_bounds))
            bounds.add(upper)
            sources = []
            if guard_bound is not None:
                sources.append("guard")
            if instruction_bound is not None:
                sources.append("instructions")
            evidence_rows.append(
                {
                    "source_unit_id": str(
                        row.get(
                            "source_unit_id",
                            row.get("unit_id", f"predecessor:{ordinal}"),
                        )
                    ),
                    "upper_exclusive": upper,
                    "sources": sources,
                }
            )
        if len(bounds) != 1:
            return _table_failure(
                kind,
                "ambiguous_index_bound",
                "incoming predecessors establish different index bounds",
            )
        source_upper_exclusive = next(iter(bounds))
        if source_upper_exclusive <= 0 or source_upper_exclusive > max_entries:
            return _table_failure(
                kind,
                "invalid_index_bound",
                "recovered index bound is empty or exceeds the resolver cap",
            )
        index_values = list(range(source_upper_exclusive))

    remap: dict[str, Any] | None = None
    if remap_shape is not None:
        assert source_upper_exclusive is not None
        remap_address, remap_index, remap_form = remap_shape
        remap_resolution = _resolve_section_address(
            remap_address,
            image_base=image_base,
            sections=sections,
            size=source_upper_exclusive,
            require_executable=False,
        )
        if remap_resolution is None:
            return _table_failure(
                kind,
                "invalid_index_remap_address",
                "byte-remap address does not identify one readable PE section range",
            )
        remap_rva, remap_section, remap_address_model = remap_resolution
        if not _section_flag(remap_section, "readable"):
            return _table_failure(
                kind,
                "unreadable_index_remap",
                "byte-remap table is not in a readable PE section",
            )
        if _section_flag(remap_section, "writable"):
            return _table_failure(
                kind,
                "writable_index_remap",
                "byte-remap table is writable and cannot bound static control",
            )
        try:
            remap_bytes = read_rva(remap_rva, source_upper_exclusive)
        except Exception:
            return _table_failure(
                kind,
                "unreadable_index_remap",
                "byte-remap bytes could not be read",
            )
        if (
            not isinstance(remap_bytes, bytes)
            or len(remap_bytes) != source_upper_exclusive
        ):
            return _table_failure(
                kind,
                "unreadable_index_remap",
                "byte-remap reader did not return the exact requested bytes",
            )
        index_values = sorted(set(remap_bytes))
        if not index_values:
            return _table_failure(
                kind,
                "empty_index_remap",
                "byte-remap table has no values",
            )
        if len(index_values) > max_entries:
            return _table_failure(
                kind,
                "invalid_index_bound",
                "byte-remap output exceeds the resolver cap",
            )
        remap = {
            "kind": "immutable_u8_lookup",
            "expression_form": remap_form,
            "source_expression": copy.deepcopy(dict(remap_index)),
            "source_upper_exclusive": source_upper_exclusive,
            "address": remap_address,
            "address_model": remap_address_model,
            "rva_start": remap_rva,
            "rva_end": remap_rva + source_upper_exclusive,
            "section": _section_name(remap_section),
            "bytes_sha256": sha256(remap_bytes).hexdigest(),
            "bytes_le": list(remap_bytes),
            "possible_values": index_values,
        }

    table_resolution = _resolve_section_address(
        table_address,
        image_base=image_base,
        sections=sections,
        size=1,
        require_executable=False,
    )
    if table_resolution is None:
        return _table_failure(
            kind,
            "invalid_table_address",
            "table address does not identify one readable PE section range",
        )
    table_rva, table_section, address_model = table_resolution
    if not _section_flag(table_section, "readable"):
        return _table_failure(
            kind,
            "unreadable_table",
            "jump table is not in a readable PE section",
        )
    if _section_flag(table_section, "writable"):
        return _table_failure(
            kind,
            "writable_table",
            "jump table is writable and cannot define a static target inventory",
        )

    allowed_targets = None
    if valid_target_rvas is not None:
        values = list(valid_target_rvas)
        if any(not _is_u32(value) for value in values):
            return _table_failure(
                kind,
                "invalid_target_domain",
                "valid_target_rvas contains a non-PE32 value",
            )
        allowed_targets = frozenset(int(value) for value in values)

    entries: list[dict[str, Any]] = []
    table_bytes_by_index: list[tuple[int, int, bytes]] = []
    for index in index_values:
        entry_address = (table_address + index * 4) & 0xFFFFFFFF
        entry_resolution = _resolve_section_address(
            entry_address,
            image_base=image_base,
            sections=sections,
            size=4,
            require_executable=False,
        )
        if entry_resolution is None:
            return _table_failure(
                kind,
                "invalid_table_address",
                f"jump-table index {index} does not identify one PE32 table entry",
            )
        entry_rva, entry_section, entry_address_model = entry_resolution
        if (
            not _section_flag(entry_section, "readable")
            or _section_flag(entry_section, "writable")
            or _section_name(entry_section) != _section_name(table_section)
        ):
            failure_code = (
                "writable_table"
                if _section_flag(entry_section, "writable")
                else "invalid_table_address"
            )
            return _table_failure(
                kind,
                failure_code,
                (
                    "jump-table entries do not remain in one immutable "
                    "readable section"
                ),
            )
        try:
            raw = read_rva(entry_rva, 4)
        except Exception:
            return _table_failure(
                kind,
                "unreadable_table",
                "jump-table bytes could not be read",
            )
        if not isinstance(raw, bytes) or len(raw) != 4:
            return _table_failure(
                kind,
                "unreadable_table",
                "jump-table reader did not return one exact entry",
            )
        table_bytes_by_index.append((index, entry_rva, raw))
        target_address = int.from_bytes(raw, "little")
        resolution = _resolve_section_address(
            target_address,
            image_base=image_base,
            sections=sections,
            size=1,
            require_executable=True,
        )
        if resolution is None:
            return _table_failure(
                kind,
                "invalid_table_target",
                f"jump-table entry {index} does not identify executable PE32 code",
            )
        target_rva, target_section, target_address_model = resolution
        if allowed_targets is not None and target_rva not in allowed_targets:
            return _table_failure(
                kind,
                "invalid_table_target",
                f"jump-table entry {index} is not a declared unit start",
            )
        entries.append(
            {
                "index": index,
                "entry_address": entry_address,
                "entry_address_model": entry_address_model,
                "entry_rva": entry_rva,
                "bytes_le": list(raw),
                "target_address": target_address,
                "target_address_model": target_address_model,
                "target_rva": target_rva,
                "target_section": _section_name(target_section),
            }
        )

    target_rvas = sorted({int(entry["target_rva"]) for entry in entries})
    entry_rvas = sorted(int(entry["entry_rva"]) for entry in entries)
    contiguous = entry_rvas == list(
        range(entry_rvas[0], entry_rvas[0] + len(entry_rvas) * 4, 4)
    )
    contiguous_from_zero = index_values == list(range(len(index_values)))
    # The range hash always follows ascending address order.  The inventory hash
    # separately preserves semantic index order, including wrapped negative
    # indices represented as uint32 values.
    table_bytes = b"".join(
        raw for _index, _entry_rva, raw in sorted(
            table_bytes_by_index, key=lambda item: item[1]
        )
    )
    table_inventory = b"".join(
        index.to_bytes(4, "little") + raw
        for index, _entry_rva, raw in table_bytes_by_index
    )
    return {
        "status": "recovered",
        "closure": "checked_finite_target_inventory",
        "kind": kind,
        "index": {
            "expression": copy.deepcopy(dict(index_expression)),
            "lower_inclusive": 0 if contiguous_from_zero else None,
            "upper_exclusive": len(index_values) if contiguous_from_zero else None,
            "values": index_values,
            "value_count": len(index_values),
            "dataflow_evidence": dataflow_evidence,
            "remap": remap,
            "bound_evidence": sorted(
                evidence_rows,
                key=_canonical_mapping_key,
            ),
        },
        "table": {
            "address": table_address,
            "address_model": address_model,
            "expression_form": expression_form,
            "rva_start": entry_rvas[0],
            "rva_end": entry_rvas[-1] + 4,
            "entry_width": 4,
            "entry_count": len(index_values),
            "index_values": index_values,
            "contiguous": contiguous,
            "section": _section_name(table_section),
            "bytes_sha256": sha256(table_bytes).hexdigest(),
            "inventory_sha256": sha256(table_inventory).hexdigest(),
        },
        "entries": entries,
        "target_rvas": target_rvas,
        "failure": None,
    }


def _table_failure(kind: str, code: str, message: str) -> dict[str, Any]:
    return {
        "status": "incomplete",
        "closure": "unresolved",
        "kind": kind,
        "index": None,
        "table": None,
        "entries": [],
        "target_rvas": [],
        "failure": {"code": code, "message": message},
    }


def _indexed_load_shape(
    expression: Mapping[str, Any],
) -> tuple[int, Mapping[str, Any], str] | None:
    if not isinstance(expression, Mapping):
        return None
    op = str(expression.get("op", "")).lower()
    if op == "read32":
        address = expression.get("address")
    elif op == "load":
        width = expression.get("width")
        width_bits = expression.get("width_bits")
        if width not in (None, 4) or width_bits not in (None, 32):
            return None
        if width is None and width_bits is None:
            return None
        address = expression.get("address")
    else:
        return None
    operands = _binary_operands(address, "add")
    if operands is None:
        return None
    candidates = []
    for base_expression, scaled_expression in (operands, reversed(operands)):
        base = _constant_value(base_expression)
        scaled = _scaled_index(scaled_expression)
        if base is not None and scaled is not None:
            index, form = scaled
            candidates.append((base, index, form))
    unique = {
        (base, _canonical_json(index), form): (base, index, form)
        for base, index, form in candidates
    }
    if len(unique) != 1:
        return None
    return next(iter(unique.values()))


def _scaled_index(expression: Any) -> tuple[Mapping[str, Any], str] | None:
    if not isinstance(expression, Mapping):
        return None
    op = str(expression.get("op", "")).lower()
    if op in {"shift_left", "shl", "shl32"}:
        amount = expression.get("amount")
        if _constant_value(amount) == 2 or amount == 2:
            value = expression.get("value", expression.get("left"))
            if isinstance(value, Mapping):
                return value, "shift_left_2"
    if op in {"mul", "multiply", "mul32"}:
        operands = _binary_operands(expression, op)
        if operands is not None:
            for constant, index in (operands, reversed(operands)):
                if _constant_value(constant) == 4 and isinstance(index, Mapping):
                    return index, "multiply_4"
    return None


def _immutable_byte_remap_shape(
    expression: Mapping[str, Any],
) -> tuple[int, Mapping[str, Any], str] | None:
    byte_load = _strip_u8_preserving_operations(expression)
    if byte_load is None:
        return None
    address = byte_load.get("address")
    operands = _binary_operands(address, "add")
    if operands is None:
        return None
    candidates: list[tuple[int, Mapping[str, Any], str]] = []
    for base_expression, index_expression in (operands, reversed(operands)):
        base = _constant_value(base_expression)
        if base is not None and isinstance(index_expression, Mapping):
            candidates.append((base, index_expression, "base_plus_index"))
    unique = {
        (base, _canonical_json(index), form): (base, index, form)
        for base, index, form in candidates
    }
    return next(iter(unique.values())) if len(unique) == 1 else None


def _strip_u8_preserving_operations(
    expression: Any,
) -> Mapping[str, Any] | None:
    if not isinstance(expression, Mapping):
        return None
    op = str(expression.get("op", "")).lower()
    if op in {"load", "read8", "mem8"}:
        width = expression.get("width")
        width_bits = expression.get("width_bits")
        if op == "load" and width not in {1, None}:
            return None
        if op == "load" and width is None and width_bits != 8:
            return None
        if op != "load" and width_bits not in {8, None}:
            return None
        return expression
    if op in {"and", "and32", "bit_and"}:
        operands = _binary_operands(expression, op)
        if operands is None:
            return None
        for mask_expression, value_expression in (operands, reversed(operands)):
            mask = _constant_expression_value(mask_expression)
            if mask is not None and mask & 0xFF == 0xFF:
                stripped = _strip_u8_preserving_operations(value_expression)
                if stripped is not None:
                    return stripped
        return None
    if op in {"or", "or32", "bit_or"}:
        operands = _binary_operands(expression, op)
        if operands is None:
            return None
        for zero_expression, value_expression in (operands, reversed(operands)):
            if _constant_expression_value(zero_expression) == 0:
                stripped = _strip_u8_preserving_operations(value_expression)
                if stripped is not None:
                    return stripped
    return None


def _constant_expression_value(expression: Any) -> int | None:
    direct = _constant_value(expression)
    if direct is not None:
        return direct & 0xFFFFFFFF
    if not isinstance(expression, Mapping):
        return None
    op = str(expression.get("op", "")).lower()
    operands = _binary_operands(expression, op)
    if operands is None:
        return None
    left = _constant_expression_value(operands[0])
    right = _constant_expression_value(operands[1])
    if left is None or right is None:
        return None
    if op in {"and", "and32", "bit_and"}:
        return left & right
    if op in {"or", "or32", "bit_or"}:
        return left | right
    if op in {"add", "add32"}:
        return (left + right) & 0xFFFFFFFF
    if op in {"sub", "sub32"}:
        return (left - right) & 0xFFFFFFFF
    if op in {"mul", "multiply", "mul32"}:
        return (left * right) & 0xFFFFFFFF
    return None


def _predecessor_path_guard(row: Mapping[str, Any]) -> Mapping[str, Any] | None:
    for key in ("guard", "edge_guard"):
        value = row.get(key)
        if isinstance(value, Mapping):
            return value
    edge = row.get("edge")
    if isinstance(edge, Mapping) and isinstance(edge.get("guard"), Mapping):
        return edge["guard"]
    condition = row.get("condition")
    edge_kind = str(row.get("edge_kind", row.get("reaches_on", ""))).lower()
    if isinstance(condition, Mapping):
        if edge_kind in {"taken", "true"}:
            return condition
        if edge_kind in {"fallthrough", "not_taken", "false"}:
            return {"op": "not", "value": condition}
    return None


def _predecessor_output_expression(
    row: Mapping[str, Any], expression: Mapping[str, Any]
) -> Mapping[str, Any]:
    """Substitute exact final predecessor register expressions.

    The dispatch expression is evaluated after its direct predecessor.  A
    predecessor guard therefore constrains the predecessor's exact final
    value, not the dispatch unit's syntactic pre-state register.  Ambiguous or
    malformed output inventories deliberately leave the expression unchanged.
    """

    outputs = row.get("register_outputs")
    if not isinstance(outputs, Sequence) or isinstance(outputs, (str, bytes)):
        return expression
    by_register: dict[str, Mapping[str, Any]] = {}
    ambiguous: set[str] = set()
    for output in outputs:
        if not isinstance(output, Mapping):
            continue
        register = output.get("register")
        value = output.get("value")
        if not isinstance(register, str) or not isinstance(value, Mapping):
            continue
        if register in by_register:
            ambiguous.add(register)
        else:
            by_register[register] = value

    def rewrite(value: Any, active: frozenset[str]) -> Any:
        if not isinstance(value, Mapping):
            if isinstance(value, list):
                return [rewrite(item, active) for item in value]
            return value
        if str(value.get("op", "")).lower() in {"reg", "register"}:
            name = value.get("name", value.get("register"))
            if (
                isinstance(name, str)
                and name not in ambiguous
                and name not in active
                and name in by_register
            ):
                return rewrite(by_register[name], active | {name})
        return {key: rewrite(child, active) for key, child in value.items()}

    rewritten = rewrite(expression, frozenset())
    return rewritten if isinstance(rewritten, Mapping) else expression


def _guard_upper_exclusive(guard: Any, index: Mapping[str, Any]) -> int | None:
    if not isinstance(guard, Mapping):
        return None
    machine_bound = _machine_complemented_unsigned_above_bound(guard, index)
    if machine_bound is not None:
        return machine_bound
    op = str(guard.get("op", "")).lower()
    operands = _binary_operands(guard, op)
    if op in _UNSIGNED_LESS_OPS and operands is not None:
        left, right = operands
        upper = _constant_value(right)
        if _same_expression(left, index) and upper is not None and 0 < upper <= 0xFFFFFFFF:
            return upper
    if op in _UNSIGNED_LESS_EQUAL_OPS and operands is not None:
        left, right = operands
        upper = _constant_value(right)
        if _same_expression(left, index) and upper is not None and 0 <= upper < 0xFFFFFFFF:
            return upper + 1
    if op == "not" and isinstance(guard.get("value"), Mapping):
        inner = guard["value"]
        inner_op = str(inner.get("op", "")).lower()
        inner_operands = _binary_operands(inner, inner_op)
        if inner_op in _UNSIGNED_LESS_OPS and inner_operands is not None:
            lower, value = inner_operands
            limit = _constant_value(lower)
            if limit is not None and _same_expression(value, index) and limit < 0xFFFFFFFF:
                return limit + 1
        composite = _negated_greater_upper(inner, index)
        if composite is not None:
            return composite
    if op == "or" and operands is not None:
        less_bound = None
        equal_bound = None
        for child in operands:
            if not isinstance(child, Mapping):
                return None
            child_op = str(child.get("op", "")).lower()
            if child_op in _UNSIGNED_LESS_OPS:
                less_bound = _guard_upper_exclusive(child, index)
            elif child_op == "equal":
                equal_bound = _index_equal_constant(child, index)
        if less_bound is not None and equal_bound == less_bound:
            return less_bound + 1
    return None


def _unary_operand(value: Any, operation: str) -> Any | None:
    if (
        not isinstance(value, Mapping)
        or str(value.get("op", "")).lower() != operation
    ):
        return None
    if "value" in value:
        return value["value"]
    arguments = value.get("args")
    if (
        isinstance(arguments, Sequence)
        and not isinstance(arguments, (str, bytes))
        and len(arguments) == 1
    ):
        return arguments[0]
    return None


def _selector_mask(expression: Mapping[str, Any]) -> int | None:
    operation = str(expression.get("op", "")).lower()
    if operation in {"load", "read8", "read32"}:
        width = expression.get("width")
        if width is None:
            width = 1 if operation == "read8" else 4 if operation == "read32" else None
        if isinstance(width, int) and not isinstance(width, bool) and width in {1, 2, 4}:
            return (1 << (width * 8)) - 1
    if operation in {"and", "and32", "bit_and"}:
        operands = _binary_operands(expression, operation)
        if operands is not None:
            for candidate, mask_value in (operands, reversed(operands)):
                mask = _constant_value(mask_value)
                if (
                    mask is not None
                    and isinstance(candidate, Mapping)
                    and mask == _selector_mask(candidate)
                ):
                    return mask
    return None


def _same_selector_value(value: Any, selector: Mapping[str, Any]) -> bool:
    if _same_expression(value, selector):
        return True
    if not isinstance(value, Mapping):
        return False
    operation = str(value.get("op", "")).lower()
    operands = (
        _binary_operands(value, operation)
        if operation in {"and", "and32", "bit_and"}
        else None
    )
    if operands is None:
        return False
    mask = _selector_mask(selector)
    return mask is not None and any(
        _constant_value(mask_value) == mask
        and _same_expression(candidate, selector)
        for candidate, mask_value in (operands, reversed(operands))
    )


def _machine_zero_comparison_bound(
    value: Any, selector: Mapping[str, Any]
) -> int | None:
    operands = _binary_operands(value, "eq")
    if operands is None:
        return None
    expression = None
    for candidate, zero in (operands, reversed(operands)):
        if _constant_value(zero) == 0:
            expression = candidate
            break
    if expression is None:
        return None
    if isinstance(expression, Mapping):
        operation = str(expression.get("op", "")).lower()
        masked = (
            _binary_operands(expression, operation)
            if operation in {"and", "and32", "bit_and"}
            else None
        )
        mask = _selector_mask(selector)
        if masked is not None and mask is not None:
            for candidate, mask_value in (masked, reversed(masked)):
                if _constant_value(mask_value) == mask:
                    expression = candidate
                    break
    operation = (
        str(expression.get("op", "")).lower()
        if isinstance(expression, Mapping)
        else ""
    )
    subtraction = (
        _binary_operands(expression, operation)
        if operation in {"sub", "sub32"}
        else None
    )
    if subtraction is None or not _same_selector_value(subtraction[0], selector):
        return None
    return _constant_value(subtraction[1])


def _machine_unsigned_less_bound(
    value: Any, selector: Mapping[str, Any]
) -> int | None:
    if not isinstance(value, Mapping):
        return None
    operation = str(value.get("op", "")).lower()
    if operation not in _UNSIGNED_LESS_OPS:
        return None
    operands = _binary_operands(value, operation)
    if operands is None or not _same_selector_value(operands[0], selector):
        return None
    return _constant_value(operands[1])


def _machine_complemented_unsigned_above_bound(
    condition: Any, selector: Mapping[str, Any]
) -> int | None:
    """Recognize exact expanded x86 ``cmp selector,N; ja fallback`` semantics."""

    inner = _unary_operand(condition, "not")
    operands = _binary_operands(inner, "and_bool")
    if operands is None:
        return None
    zero_bounds: list[int] = []
    less_bounds: list[int] = []
    for operand in operands:
        predicate = _unary_operand(operand, "not")
        if predicate is None:
            return None
        zero = _machine_zero_comparison_bound(predicate, selector)
        less = _machine_unsigned_less_bound(predicate, selector)
        if zero is not None:
            zero_bounds.append(zero)
        elif less is not None:
            less_bounds.append(less)
        else:
            return None
    if (
        len(zero_bounds) != 1
        or len(less_bounds) != 1
        or zero_bounds[0] != less_bounds[0]
        or zero_bounds[0] >= 0xFFFF_FFFF
    ):
        return None
    return zero_bounds[0] + 1


def _negated_greater_upper(inner: Mapping[str, Any], index: Mapping[str, Any]) -> int | None:
    if str(inner.get("op", "")).lower() not in {"and", "bit_and"}:
        return None
    children = _binary_operands(inner, str(inner.get("op", "")).lower())
    if children is None:
        return None
    less_limit = None
    unequal_limit = None
    for child in children:
        if not isinstance(child, Mapping) or str(child.get("op", "")).lower() != "not":
            return None
        predicate = child.get("value")
        if not isinstance(predicate, Mapping):
            return None
        predicate_op = str(predicate.get("op", "")).lower()
        predicate_operands = _binary_operands(predicate, predicate_op)
        if predicate_op in _UNSIGNED_LESS_OPS and predicate_operands is not None:
            left, right = predicate_operands
            limit = _constant_value(right)
            if not _same_expression(left, index) or limit is None:
                return None
            less_limit = limit
        elif predicate_op == "equal":
            unequal_limit = _subtraction_zero_limit(predicate, index)
        else:
            return None
    if less_limit is None or unequal_limit != less_limit or less_limit >= 0xFFFFFFFF:
        return None
    return less_limit + 1


def _subtraction_zero_limit(predicate: Mapping[str, Any], index: Mapping[str, Any]) -> int | None:
    operands = _binary_operands(predicate, "equal")
    if operands is None:
        return None
    left, right = operands
    if _constant_value(left) == 0:
        left, right = right, left
    if _constant_value(right) != 0 or not isinstance(left, Mapping):
        return None
    subtraction = _binary_operands(left, "sub")
    if subtraction is None:
        return None
    value, limit_expression = subtraction
    limit = _constant_value(limit_expression)
    return limit if limit is not None and _same_expression(value, index) else None


def _index_equal_constant(predicate: Mapping[str, Any], index: Mapping[str, Any]) -> int | None:
    operands = _binary_operands(predicate, "equal")
    if operands is None:
        return None
    for value, constant in (operands, reversed(operands)):
        limit = _constant_value(constant)
        if limit is not None and _same_expression(value, index):
            return limit
    return None


def _instruction_upper_exclusive(
    row: Mapping[str, Any], index: Mapping[str, Any]
) -> int | None:
    instructions = row.get("instructions")
    if not isinstance(instructions, Sequence) or isinstance(instructions, (str, bytes)):
        return None
    index_register = _index_register(index)
    edge_kind = str(row.get("edge_kind", row.get("reaches_on", ""))).lower()
    if index_register is None or edge_kind not in {
        "taken",
        "true",
        "fallthrough",
        "not_taken",
        "false",
    }:
        return None
    branch_index = None
    branch_mnemonic = None
    for position in range(len(instructions) - 1, -1, -1):
        instruction = instructions[position]
        if not isinstance(instruction, Mapping):
            continue
        mnemonic = str(instruction.get("mnemonic", "")).lower()
        if mnemonic.startswith("j"):
            branch_index = position
            branch_mnemonic = mnemonic
            break
    if branch_index is None or branch_mnemonic is None:
        return None
    compare = None
    for position in range(branch_index - 1, -1, -1):
        instruction = instructions[position]
        if isinstance(instruction, Mapping) and str(
            instruction.get("mnemonic", "")
        ).lower() == "cmp":
            compare = instruction
            break
    if compare is None:
        return None
    operands = compare.get("operands")
    if not isinstance(operands, Sequence) or len(operands) != 2:
        return None
    register = _instruction_register(operands[0])
    immediate = _instruction_immediate(operands[1])
    if register != index_register or immediate is None or not 0 <= immediate <= 0xFFFFFFFF:
        return None
    taken = edge_kind in {"taken", "true"}
    if branch_mnemonic in {"jb", "jnae", "jc"} and taken:
        return immediate if immediate > 0 else None
    if branch_mnemonic in {"jae", "jnb", "jnc"} and not taken:
        return immediate if immediate > 0 else None
    if branch_mnemonic in {"jbe", "jna"} and taken and immediate < 0xFFFFFFFF:
        return immediate + 1
    if branch_mnemonic in {"ja", "jnbe"} and not taken and immediate < 0xFFFFFFFF:
        return immediate + 1
    return None


def _resolve_section_address(
    value: int,
    *,
    image_base: int,
    sections: Sequence[Mapping[str, Any] | Any],
    size: int,
    require_executable: bool,
) -> tuple[int, Mapping[str, Any] | Any, str] | None:
    if not _is_u32(value) or size <= 0:
        return None
    candidates: dict[int, set[str]] = {}
    candidates.setdefault(value, set()).add("rva")
    if value >= image_base:
        candidates.setdefault(value - image_base, set()).add("va")
    resolved = []
    for rva, models in candidates.items():
        if not _is_u32(rva) or rva + size > 0x100000000:
            continue
        matches = [
            section
            for section in sections
            if _section_covers(section, rva, rva + size)
            and (not require_executable or _section_flag(section, "executable"))
        ]
        if len(matches) == 1:
            model = "va_or_rva" if len(models) > 1 else next(iter(models))
            resolved.append((rva, matches[0], model))
        elif len(matches) > 1:
            return None
    if len(resolved) != 1:
        return None
    return resolved[0]


def _section_covers(section: Mapping[str, Any] | Any, start: int, end: int) -> bool:
    rva_start = _field(section, "rva_start")
    rva_end = _field(section, "rva_end")
    return (
        _is_u32(rva_start)
        and isinstance(rva_end, int)
        and not isinstance(rva_end, bool)
        and rva_start <= start < end <= rva_end <= 0x100000000
    )


def _section_flag(section: Mapping[str, Any] | Any, name: str) -> bool:
    return _field(section, name) is True


def _section_name(section: Mapping[str, Any] | Any) -> str | None:
    value = _field(section, "name")
    return str(value) if value is not None else None


def _field(value: Mapping[str, Any] | Any, name: str) -> Any:
    return value.get(name) if isinstance(value, Mapping) else getattr(value, name, None)

"""Non-authoritative C rendering for recovered Stage B operations.

This module deliberately has no dependency on source-call substitution.  An
operation catalog describes how an already identified operation may be written
as C; it does not establish the operation's semantics or qualify a candidate.
Rendering fails closed when catalog or recovery evidence is not
exact enough to select one spelling.
"""

from __future__ import annotations

import copy
import json
import re
from hashlib import sha256
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from .artifact_formats import (
    SOURCE_OPERATION_CATALOG_FORMAT,
    SOURCE_OPERATION_RENDERING_FORMAT,
)

def _non_authoritative_rendering_metadata() -> dict[str, Any]:
    return {
        "authority": "non-authoritative",
        "authorizes_operation_semantics": False,
        "authorizes_candidate_qualification": False,
        "candidate_validation_required": True,
    }


NON_AUTHORITATIVE_RENDERING_METADATA = _non_authoritative_rendering_metadata()

_CATALOG_FIELDS = frozenset({
    "format",
    "catalog_id",
    "operation_profile_sha256",
    "entries",
    "rendering_metadata",
})
_ENTRY_FIELDS = frozenset({"id", "operation_id", "rendering"})
_DIRECT_IMPORT_FIELDS = frozenset({"kind", "symbol", "headers"})
_COM_METHOD_FIELDS = frozenset({"kind", "method", "headers"})
_C_TABLE_METHOD_FIELDS = frozenset({
    "kind",
    "table_member",
    "method",
    "pass_receiver",
    "headers",
})
_RESOLVER_POINTER_FIELDS = frozenset({"kind", "pointer_type", "headers"})
_TYPED_POINTER_FIELDS = frozenset({"kind", "pointer_type", "headers"})
_FINITE_DISPATCH_FIELDS = frozenset({"kind", "alternatives"})
_DISPATCH_ALTERNATIVE_FIELDS = frozenset({"value", "rendering"})
_RENDERING_KINDS = frozenset({
    "direct_import",
    "com_table_method",
    "c_table_method",
    "resolver_function_pointer",
    "typed_function_pointer",
    "finite_dispatch",
})
_STABLE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@+-]*\Z")
_C_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_HEADER = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_./+-]*\Z")
_HEX_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class SourceOperationCatalogError(ValueError):
    """A source-operation catalog or its profile binding is malformed."""


class _RenderingGap(Exception):
    def __init__(
        self,
        reason: str,
        required_action: str,
        *,
        details: Mapping[str, Any] | None = None,
    ) -> None:
        super().__init__(reason)
        self.reason = reason
        self.required_action = required_action
        self.details = dict(details or {})


def bind_source_operation_catalog(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Strictly validate and self-hash a source-operation catalog.

    Multiple entries may name the same operation ID so an incomplete catalog
    can still be inspected.  Such an ID is intentionally unrenderable and is
    reported as an ambiguity by :func:`render_source_operations`.
    """

    catalog = copy.deepcopy(dict(_object(payload, "source-operation catalog")))
    supplied_sha256 = catalog.pop("catalog_sha256", None)
    _exact_fields(catalog, _CATALOG_FIELDS, "source-operation catalog")
    if catalog["format"] != SOURCE_OPERATION_CATALOG_FORMAT:
        raise SourceOperationCatalogError(
            "unsupported source-operation catalog format"
        )
    _stable_identifier(catalog["catalog_id"], "source-operation catalog ID")
    _digest(
        catalog["operation_profile_sha256"],
        "source-operation catalog operation profile SHA-256",
    )
    _validate_non_authoritative_metadata(catalog["rendering_metadata"])

    entry_ids: set[str] = set()
    entries = _array(catalog["entries"], "source-operation catalog entries")
    for index, raw_entry in enumerate(entries):
        context = f"source-operation catalog entry {index}"
        entry = _object(raw_entry, context)
        _exact_fields(entry, _ENTRY_FIELDS, context)
        entry_id = _stable_identifier(entry["id"], f"{context} ID")
        if entry_id in entry_ids:
            raise SourceOperationCatalogError(
                f"duplicate source-operation catalog entry ID: {entry_id}"
            )
        entry_ids.add(entry_id)
        _stable_identifier(entry["operation_id"], f"{context} operation ID")
        _validate_rendering(entry["rendering"], f"{context} rendering")

    computed_sha256 = _canonical_sha256(catalog)
    if supplied_sha256 is not None and _digest(
        supplied_sha256, "source-operation catalog SHA-256"
    ) != computed_sha256:
        raise SourceOperationCatalogError("stale source-operation catalog SHA-256")
    return {**catalog, "catalog_sha256": computed_sha256}


def load_source_operation_catalog(path: Path | str) -> dict[str, Any]:
    """Load, strictly validate, and hash a JSON source-operation catalog."""

    catalog_path = Path(path)
    try:
        payload = json.loads(catalog_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise SourceOperationCatalogError(
            f"cannot read source-operation catalog {catalog_path}: {error}"
        ) from error
    return bind_source_operation_catalog(
        _object(payload, f"source-operation catalog {catalog_path}")
    )


def render_source_operations(
    *,
    catalog: Path | str | Mapping[str, Any],
    operation_profile_sha256: str,
    operations: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    """Render operation evidence rows or return deterministic repair items.

    Evidence rows require ``operation_id`` and ordered ``arguments`` (the alias
    ``recovered_arguments`` is also accepted).  Method rows additionally need
    ``receiver``; resolver-pointer rows need ``resolver_result``; finite
    dispatch rows need an explicit selector expression and possible-value set.
    Expressions are carried through conservatively and are never inferred.
    """

    bound = (
        load_source_operation_catalog(catalog)
        if isinstance(catalog, (str, Path))
        else bind_source_operation_catalog(catalog)
    )
    expected_profile_sha256 = _digest(
        operation_profile_sha256, "operation profile SHA-256"
    )
    if bound["operation_profile_sha256"] != expected_profile_sha256:
        raise SourceOperationCatalogError(
            "source-operation catalog is bound to a different operation profile"
        )
    if isinstance(operations, (str, bytes, Mapping)):
        raise SourceOperationCatalogError("operation evidence rows must be iterable")

    entries_by_operation: dict[str, list[Mapping[str, Any]]] = {}
    for entry in bound["entries"]:
        entries_by_operation.setdefault(str(entry["operation_id"]), []).append(entry)

    rendered_rows: list[dict[str, Any]] = []
    repair_items: list[dict[str, Any]] = []
    required_headers: set[str] = set()
    for index, raw_operation in enumerate(operations):
        operation = _object(raw_operation, f"operation evidence row {index}")
        operation_id = _stable_identifier(
            operation.get("operation_id"),
            f"operation evidence row {index} operation ID",
        )
        evidence_id = _evidence_id(operation, operation_id, index)
        candidates = entries_by_operation.get(operation_id, [])
        try:
            if not candidates:
                raise _RenderingGap(
                    "missing_catalog_entry",
                    "add_one_catalog_entry_for_operation_id",
                )
            if len(candidates) != 1:
                raise _RenderingGap(
                    "ambiguous_catalog_entry",
                    "leave_exactly_one_catalog_entry_for_operation_id",
                    details={
                        "candidate_entry_ids": sorted(
                            str(entry["id"]) for entry in candidates
                        )
                    },
                )
            entry = candidates[0]
            arguments = _operation_arguments(operation)
            call_expression, alternatives, headers = _render_specification(
                entry["rendering"], operation, arguments
            )
        except _RenderingGap as gap:
            repair = _repair_item(
                index=index,
                evidence_id=evidence_id,
                operation_id=operation_id,
                gap=gap,
                catalog_entry_ids=[str(entry["id"]) for entry in candidates],
            )
            repair_items.append(repair)
            rendered_rows.append({
                "evidence_id": evidence_id,
                "operation_id": operation_id,
                "status": "repair_required",
                "catalog_entry_id": None,
                "call_expression": None,
                "dispatch_alternatives": [],
                "required_headers": [],
                "repair_item_id": repair["id"],
            })
            continue

        required_headers.update(headers)
        rendered_rows.append({
            "evidence_id": evidence_id,
            "operation_id": operation_id,
            "status": "rendered",
            "catalog_entry_id": str(entry["id"]),
            "rendering_kind": str(entry["rendering"]["kind"]),
            "call_expression": call_expression,
            "dispatch_alternatives": alternatives,
            "required_headers": sorted(headers),
            "repair_item_id": None,
        })

    core = {
        "format": SOURCE_OPERATION_RENDERING_FORMAT,
        "status": "complete" if not repair_items else "incomplete",
        "operation_profile_sha256": expected_profile_sha256,
        "catalog_id": bound["catalog_id"],
        "catalog_sha256": bound["catalog_sha256"],
        "operations": rendered_rows,
        "required_headers": sorted(required_headers),
        "repair_items": repair_items,
        "counts": {
            "operations": len(rendered_rows),
            "rendered": sum(row["status"] == "rendered" for row in rendered_rows),
            "repair_required": len(repair_items),
        },
        "rendering_metadata": _non_authoritative_rendering_metadata(),
    }
    return {**core, "rendering_sha256": _canonical_sha256(core)}


def render_source_operation_rows(
    *,
    catalog: Path | str | Mapping[str, Any],
    operation_profile_sha256: str,
    operation_evidence_rows: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    """Named-row wrapper for callers that use the evidence artifact wording."""

    return render_source_operations(
        catalog=catalog,
        operation_profile_sha256=operation_profile_sha256,
        operations=operation_evidence_rows,
    )


def _validate_non_authoritative_metadata(value: Any) -> None:
    metadata = _object(value, "source-operation rendering metadata")
    _exact_fields(
        metadata,
        frozenset(_non_authoritative_rendering_metadata()),
        "source-operation rendering metadata",
    )
    if (
        metadata.get("authority") != "non-authoritative"
        or metadata.get("authorizes_operation_semantics") is not False
        or metadata.get("authorizes_candidate_qualification") is not False
        or metadata.get("candidate_validation_required") is not True
    ):
        raise SourceOperationCatalogError(
            "source-operation rendering metadata must remain non-authoritative"
        )


def _validate_rendering(
    value: Any,
    context: str,
    *,
    allow_dispatch: bool = True,
) -> None:
    rendering = _object(value, context)
    kind = rendering.get("kind")
    if kind not in _RENDERING_KINDS:
        raise SourceOperationCatalogError(f"{context} has unsupported kind")
    if kind == "direct_import":
        _exact_fields(rendering, _DIRECT_IMPORT_FIELDS, context)
        _c_identifier(rendering["symbol"], f"{context} symbol")
        _headers(rendering["headers"], context)
        return
    if kind == "com_table_method":
        _exact_fields(rendering, _COM_METHOD_FIELDS, context)
        _c_identifier(rendering["method"], f"{context} method")
        _headers(rendering["headers"], context)
        return
    if kind == "c_table_method":
        _exact_fields(rendering, _C_TABLE_METHOD_FIELDS, context)
        table_member = rendering["table_member"]
        if table_member is not None:
            _c_identifier(table_member, f"{context} table member")
        _c_identifier(rendering["method"], f"{context} method")
        if not isinstance(rendering["pass_receiver"], bool):
            raise SourceOperationCatalogError(
                f"{context} pass_receiver must be a boolean"
            )
        _headers(rendering["headers"], context)
        return
    if kind == "resolver_function_pointer":
        _exact_fields(rendering, _RESOLVER_POINTER_FIELDS, context)
        _c_identifier(rendering["pointer_type"], f"{context} pointer type")
        _headers(rendering["headers"], context)
        return
    if kind == "typed_function_pointer":
        _exact_fields(rendering, _TYPED_POINTER_FIELDS, context)
        _c_identifier(rendering["pointer_type"], f"{context} pointer type")
        _headers(rendering["headers"], context)
        return

    _exact_fields(rendering, _FINITE_DISPATCH_FIELDS, context)
    if not allow_dispatch:
        raise SourceOperationCatalogError(
            f"{context} contains a nested finite dispatch"
        )
    alternatives = _array(rendering["alternatives"], f"{context} alternatives")
    if len(alternatives) < 2:
        raise SourceOperationCatalogError(
            f"{context} must contain at least two finite alternatives"
        )
    values: set[int] = set()
    for index, raw_alternative in enumerate(alternatives):
        alternative_context = f"{context} alternative {index}"
        alternative = _object(raw_alternative, alternative_context)
        _exact_fields(
            alternative, _DISPATCH_ALTERNATIVE_FIELDS, alternative_context
        )
        selector_value = _u32(alternative["value"], f"{alternative_context} value")
        if selector_value in values:
            raise SourceOperationCatalogError(
                f"{context} contains duplicate finite alternative value "
                f"{selector_value}"
            )
        values.add(selector_value)
        _validate_rendering(
            alternative["rendering"],
            f"{alternative_context} rendering",
            allow_dispatch=False,
        )


def _operation_arguments(operation: Mapping[str, Any]) -> tuple[str, ...]:
    present = [
        field
        for field in ("arguments", "recovered_arguments")
        if field in operation
    ]
    if not present:
        raise _RenderingGap(
            "missing_recovered_arguments", "recover_ordered_operation_arguments"
        )
    if len(present) != 1:
        raise _RenderingGap(
            "ambiguous_recovered_arguments",
            "retain_one_ordered_operation_argument_inventory",
        )
    raw_arguments = operation[present[0]]
    if not isinstance(raw_arguments, list):
        raise _RenderingGap(
            "invalid_recovered_arguments", "recover_ordered_operation_arguments"
        )

    expressions: list[tuple[int, str]] = []
    saw_index = False
    saw_unindexed = False
    for position, raw_argument in enumerate(raw_arguments):
        if isinstance(raw_argument, Mapping):
            expression = raw_argument.get("expression")
            argument_index = raw_argument.get("index")
            if argument_index is None:
                saw_unindexed = True
                argument_index = position
            else:
                saw_index = True
                if (
                    not isinstance(argument_index, int)
                    or isinstance(argument_index, bool)
                    or argument_index < 0
                ):
                    raise _RenderingGap(
                        "invalid_argument_index",
                        "recover_canonical_zero_based_argument_indices",
                    )
        else:
            saw_unindexed = True
            argument_index = position
            expression = raw_argument
        expressions.append(
            (
                argument_index,
                _c_expression_or_gap(
                    expression,
                    reason="invalid_argument_expression",
                    required_action="recover_valid_c_argument_expressions",
                ),
            )
        )
    if saw_index and saw_unindexed:
        raise _RenderingGap(
            "ambiguous_argument_order",
            "recover_canonical_zero_based_argument_indices",
        )
    if saw_index:
        indices = [index for index, _ in expressions]
        if sorted(indices) != list(range(len(expressions))):
            raise _RenderingGap(
                "noncanonical_argument_indices",
                "recover_canonical_zero_based_argument_indices",
            )
        expressions.sort()
    return tuple(expression for _, expression in expressions)


def _render_specification(
    rendering: Mapping[str, Any],
    operation: Mapping[str, Any],
    arguments: Sequence[str],
) -> tuple[str | None, list[dict[str, Any]], set[str]]:
    kind = rendering["kind"]
    if kind == "direct_import":
        return (
            _call(str(rendering["symbol"]), arguments),
            [],
            set(rendering["headers"]),
        )
    if kind == "com_table_method":
        receiver = _recovered_expression(
            operation,
            ("receiver", "recovered_receiver"),
            missing_reason="missing_recovered_receiver",
            missing_action="recover_operation_receiver",
        )
        base = _member_base(receiver)
        return (
            _call(
                f"{base}->lpVtbl->{rendering['method']}",
                (receiver, *arguments),
            ),
            [],
            set(rendering["headers"]),
        )
    if kind == "c_table_method":
        receiver = _recovered_expression(
            operation,
            ("receiver", "recovered_receiver"),
            missing_reason="missing_recovered_receiver",
            missing_action="recover_operation_receiver",
        )
        base = _member_base(receiver)
        table_member = rendering["table_member"]
        target = (
            f"{base}->{table_member}->{rendering['method']}"
            if table_member is not None
            else f"{base}->{rendering['method']}"
        )
        call_arguments: Sequence[str] = arguments
        if rendering["pass_receiver"]:
            call_arguments = (receiver, *arguments)
        return _call(target, call_arguments), [], set(rendering["headers"])
    if kind == "resolver_function_pointer":
        resolver_result = _recovered_expression(
            operation,
            ("resolver_result", "recovered_resolver_result"),
            missing_reason="missing_resolver_result",
            missing_action="recover_resolver_produced_function_pointer",
        )
        target = f"(({rendering['pointer_type']})({resolver_result}))"
        return _call(target, arguments), [], set(rendering["headers"])
    if kind == "typed_function_pointer":
        pointer = _recovered_expression(
            operation,
            ("target", "recovered_target"),
            missing_reason="missing_function_pointer_target",
            missing_action="recover_typed_function_pointer_target",
        )
        target = f"(({rendering['pointer_type']})({pointer}))"
        return _call(target, arguments), [], set(rendering["headers"])

    dispatch = operation.get("dispatch")
    if not isinstance(dispatch, Mapping):
        raise _RenderingGap(
            "missing_finite_dispatch_evidence",
            "recover_dispatch_selector_and_possible_values",
        )
    selector = _one_expression_field(
        dispatch,
        ("selector_expression", "expression"),
        missing_reason="missing_dispatch_selector",
        missing_action="recover_dispatch_selector_expression",
    )
    possible_values = _one_value_field(
        dispatch,
        ("possible_values", "values"),
        missing_reason="missing_dispatch_values",
        missing_action="recover_explicit_finite_dispatch_values",
    )
    if (
        not isinstance(possible_values, list)
        or not possible_values
        or any(
            not isinstance(value, int)
            or isinstance(value, bool)
            or value < 0
            or value >= 2**32
            for value in possible_values
        )
        or len(set(possible_values)) != len(possible_values)
    ):
        raise _RenderingGap(
            "invalid_dispatch_values",
            "recover_unique_finite_u32_dispatch_values",
        )
    alternatives_by_value = {
        int(alternative["value"]): alternative
        for alternative in rendering["alternatives"]
    }
    missing_values = sorted(set(possible_values) - set(alternatives_by_value))
    if missing_values:
        raise _RenderingGap(
            "missing_dispatch_alternative",
            "add_catalog_renderings_for_all_recovered_dispatch_values",
            details={"missing_values": missing_values},
        )

    rendered_alternatives: list[dict[str, Any]] = []
    headers: set[str] = set()
    for value in sorted(possible_values):
        alternative = alternatives_by_value[value]
        expression, nested, alternative_headers = _render_specification(
            alternative["rendering"], operation, arguments
        )
        if expression is None or nested:
            raise _RenderingGap(
                "invalid_dispatch_alternative",
                "replace_nested_dispatch_with_direct_finite_alternatives",
            )
        headers.update(alternative_headers)
        rendered_alternatives.append({
            "value": value,
            "condition": f"{_condition_base(selector)} == {value}u",
            "call_expression": expression,
            "required_headers": sorted(alternative_headers),
        })
    return None, rendered_alternatives, headers


def _recovered_expression(
    operation: Mapping[str, Any],
    fields: Sequence[str],
    *,
    missing_reason: str,
    missing_action: str,
) -> str:
    return _one_expression_field(
        operation,
        fields,
        missing_reason=missing_reason,
        missing_action=missing_action,
    )


def _one_expression_field(
    value: Mapping[str, Any],
    fields: Sequence[str],
    *,
    missing_reason: str,
    missing_action: str,
) -> str:
    present = [field for field in fields if field in value]
    if not present:
        raise _RenderingGap(missing_reason, missing_action)
    if len(present) != 1:
        raise _RenderingGap(
            f"ambiguous_{missing_reason.removeprefix('missing_')}", missing_action
        )
    raw_expression = value[present[0]]
    if isinstance(raw_expression, Mapping):
        raw_expression = raw_expression.get("expression")
    return _c_expression_or_gap(
        raw_expression,
        reason=f"invalid_{missing_reason.removeprefix('missing_')}",
        required_action=missing_action,
    )


def _one_value_field(
    value: Mapping[str, Any],
    fields: Sequence[str],
    *,
    missing_reason: str,
    missing_action: str,
) -> Any:
    present = [field for field in fields if field in value]
    if not present:
        raise _RenderingGap(missing_reason, missing_action)
    if len(present) != 1:
        raise _RenderingGap(
            f"ambiguous_{missing_reason.removeprefix('missing_')}", missing_action
        )
    return value[present[0]]


def _c_expression_or_gap(
    value: Any,
    *,
    reason: str,
    required_action: str,
) -> str:
    if not isinstance(value, str) or not value or not value.isascii():
        raise _RenderingGap(reason, required_action)
    if value != value.strip() or not _valid_c_expression_shape(value):
        raise _RenderingGap(reason, required_action)
    return value


def _valid_c_expression_shape(value: str) -> bool:
    stack: list[str] = []
    closing = {")": "(", "]": "["}
    quote: str | None = None
    escaped = False
    for index, character in enumerate(value):
        if quote is not None:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
            continue
        if character in {'"', "'"}:
            quote = character
            continue
        if character in ";\n\r{}#":
            return False
        if character == "/" and index + 1 < len(value) and value[index + 1] in "/*":
            return False
        if character in "([":
            stack.append(character)
        elif character in closing:
            if not stack or stack.pop() != closing[character]:
                return False
    return quote is None and not escaped and not stack


def _call(target: str, arguments: Sequence[str]) -> str:
    return f"{target}({', '.join(arguments)})"


def _member_base(expression: str) -> str:
    return expression if _C_IDENTIFIER.fullmatch(expression) else f"({expression})"


def _condition_base(expression: str) -> str:
    return expression if _C_IDENTIFIER.fullmatch(expression) else f"({expression})"


def _repair_item(
    *,
    index: int,
    evidence_id: str,
    operation_id: str,
    gap: _RenderingGap,
    catalog_entry_ids: Sequence[str],
) -> dict[str, Any]:
    return {
        "id": f"source-operation-repair:{index:06d}",
        "kind": "source_operation_rendering",
        "status": "incomplete",
        "reason": gap.reason,
        "operation_id": operation_id,
        "evidence_id": evidence_id,
        "evidence_index": index,
        "catalog_entry_ids": sorted(catalog_entry_ids),
        "details": gap.details,
        "required_action": gap.required_action,
    }


def _evidence_id(
    operation: Mapping[str, Any], operation_id: str, index: int
) -> str:
    value = operation.get("evidence_id")
    if value is None:
        return f"{operation_id}:{index}"
    return _stable_identifier(value, f"operation evidence row {index} evidence ID")


def _headers(value: Any, context: str) -> tuple[str, ...]:
    raw_headers = _array(value, f"{context} headers")
    headers: list[str] = []
    for index, header in enumerate(raw_headers):
        if not isinstance(header, str) or _HEADER.fullmatch(header) is None:
            raise SourceOperationCatalogError(
                f"{context} header {index} must be a canonical header path"
            )
        headers.append(header)
    if len(headers) != len(set(headers)):
        raise SourceOperationCatalogError(f"{context} headers contain duplicates")
    return tuple(headers)


def _stable_identifier(value: Any, context: str) -> str:
    if not isinstance(value, str) or _STABLE_ID.fullmatch(value) is None:
        raise SourceOperationCatalogError(
            f"{context} must be a nonempty stable ASCII identifier"
        )
    return value


def _c_identifier(value: Any, context: str) -> str:
    if not isinstance(value, str) or _C_IDENTIFIER.fullmatch(value) is None:
        raise SourceOperationCatalogError(
            f"{context} must be a C identifier"
        )
    return value


def _digest(value: Any, context: str) -> str:
    if not isinstance(value, str) or _HEX_SHA256.fullmatch(value) is None:
        raise SourceOperationCatalogError(
            f"{context} must be a lowercase SHA-256 digest"
        )
    return value


def _u32(value: Any, context: str) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < 0
        or value >= 2**32
    ):
        raise SourceOperationCatalogError(f"{context} must be a u32 value")
    return value


def _object(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise SourceOperationCatalogError(f"{context} must be a JSON object")
    if any(not isinstance(key, str) for key in value):
        raise SourceOperationCatalogError(f"{context} field names must be strings")
    return value


def _array(value: Any, context: str) -> list[Any]:
    if not isinstance(value, list):
        raise SourceOperationCatalogError(f"{context} must be an array")
    return value


def _exact_fields(
    value: Mapping[str, Any], expected: frozenset[str], context: str
) -> None:
    missing = sorted(expected - set(value))
    unexpected = sorted(set(value) - expected)
    if missing:
        raise SourceOperationCatalogError(
            f"{context} is missing required fields: {', '.join(missing)}"
        )
    if unexpected:
        raise SourceOperationCatalogError(
            f"{context} has unexpected fields: {', '.join(unexpected)}"
        )


def _canonical_sha256(value: Any) -> str:
    return sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
    ).hexdigest()


__all__ = [
    "NON_AUTHORITATIVE_RENDERING_METADATA",
    "SOURCE_OPERATION_CATALOG_FORMAT",
    "SOURCE_OPERATION_RENDERING_FORMAT",
    "SourceOperationCatalogError",
    "bind_source_operation_catalog",
    "load_source_operation_catalog",
    "render_source_operation_rows",
    "render_source_operations",
]

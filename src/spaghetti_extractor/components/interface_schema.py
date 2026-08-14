"""Schema and effect-reference primitives for component interfaces."""

from __future__ import annotations

import copy
import json
from hashlib import sha256
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from ..util import sha256_file


_IDENTITY_FIELDS = (
    "kind",
    "dll",
    "symbol",
    "ordinal",
    "target_rva",
    "return_rva",
    "identity",
    "name",
    "effect_model",
    "element_width",
    "address_size",
    "restart_semantics",
    "repeat_condition",
    "comparison_model",
)
_STRING_EVENT_ARGUMENT_FIELDS = {
    "rep_movs": ("destination", "source", "count", "direction_flag"),
    "rep_stos": ("destination", "value", "count", "direction_flag"),
    "rep_scas": ("destination", "accumulator", "count", "direction_flag"),
}
_STRING_EVENT_MODELS = {
    "rep_movs": "symbolic_string_copy_v2",
    "rep_stos": "symbolic_string_fill_v2",
    "rep_scas": "symbolic_string_scan_v1",
}


class ComponentInterfaceError(ValueError):
    """An interface input is not structurally usable JSON."""


def _outcome_leaves_component(
    outcome: Mapping[str, Any], members: set[str], machine: Mapping[str, Any]
) -> bool:
    kind = outcome.get("kind")
    if kind in {"return", "fault", "termination", "indirect_call", "indirect_jump"}:
        return True
    targets = _outcome_targets(outcome)
    if not targets:
        return False
    return any(
        target not in machine["units_by_rva"]
        or machine["units_by_rva"][target]["id"] not in members
        for target in targets
    )


def _outcome_targets(outcome: Mapping[str, Any]) -> list[int]:
    result = []
    for field in ("target_rva", "true_target_rva", "false_target_rva"):
        value = outcome.get(field)
        if isinstance(value, int) and not isinstance(value, bool):
            result.append(value)
    return result


def _control_spec(unit_id: str, outcome: Mapping[str, Any]) -> dict[str, Any]:
    kind = str(outcome.get("kind"))
    result: dict[str, Any] = {"unit_id": unit_id, "outcome_kind": kind}
    if "condition" in outcome:
        result["condition"] = copy.deepcopy(outcome["condition"])
    routes = []
    if kind == "branch":
        routes = [
            {"when": True, "target_rva": outcome.get("true_target_rva")},
            {"when": False, "target_rva": outcome.get("false_target_rva")},
        ]
    elif isinstance(outcome.get("target_rva"), int):
        routes = [{"when": "always", "target_rva": outcome["target_rva"]}]
    if routes:
        result["routes"] = routes
    if kind.startswith("indirect") and "target" in outcome:
        result["target_expression"] = copy.deepcopy(outcome["target"])
    if kind == "return" and "value" in outcome:
        result["return_target"] = copy.deepcopy(outcome["value"])
    return result


def _event_identity(event: Mapping[str, Any]) -> dict[str, Any]:
    result = {
        field: copy.deepcopy(event[field])
        for field in _IDENTITY_FIELDS
        if field in event
    }
    return _normalize_identity(result)


def _normalize_identity(identity: Mapping[str, Any]) -> dict[str, Any]:
    result = {
        field: copy.deepcopy(identity[field])
        for field in _IDENTITY_FIELDS
        if field in identity
    }
    if isinstance(result.get("dll"), str):
        result["dll"] = result["dll"].lower()
    return result


def _identity_complete(identity: Mapping[str, Any]) -> bool:
    kind = identity.get("kind")
    if kind == "external_call":
        return isinstance(identity.get("dll"), str) and (
            isinstance(identity.get("symbol"), str) or isinstance(identity.get("ordinal"), int)
        )
    if kind == "internal_call":
        return isinstance(identity.get("target_rva"), int)
    if kind in _STRING_EVENT_MODELS:
        return (
            identity.get("effect_model") == _STRING_EVENT_MODELS[kind]
            and identity.get("element_width") in {1, 2, 4}
            and identity.get("address_size") == 32
            and identity.get("restart_semantics") == "element_committed_v1"
            and (
                kind != "rep_scas"
                or (
                    identity.get("repeat_condition") == "while_not_equal_v1"
                    and identity.get("comparison_model") == "subtraction_flags_v1"
                )
            )
        )
    return isinstance(kind, str) and len(identity) > 1


def _event_arguments(event: Mapping[str, Any]) -> list[Any]:
    kind = event.get("kind")
    fields = _STRING_EVENT_ARGUMENT_FIELDS.get(str(kind))
    if fields is None:
        value = event.get("arguments", [])
        return copy.deepcopy(value) if isinstance(value, list) else []
    return [copy.deepcopy(event.get(field)) for field in fields]


def _internal_call_is_member(
    event: Mapping[str, Any], members: Iterable[str], machine: Mapping[str, Any]
) -> bool:
    target = event.get("target_rva")
    unit = machine["units_by_rva"].get(target) if isinstance(target, int) else None
    return unit is not None and unit.get("id") in set(members)


def _address_with_offset(base: Mapping[str, Any], offset: int) -> dict[str, Any]:
    if offset == 0:
        return copy.deepcopy(dict(base))
    return {
        "op": "add32",
        "args": [
            copy.deepcopy(dict(base)),
            {"op": "const", "value": offset & 0xFFFFFFFF, "width": 32},
        ],
    }


def _addresses_equal(left: Any, right: Any) -> bool:
    return left == right or _decompose_address(left) == _decompose_address(right)


def _decompose_address(value: Any) -> tuple[str, int] | None:
    if not isinstance(value, Mapping):
        return None
    op = value.get("op")
    if op in {"reg", "load"}:
        return (_canonical_json(value), 0)
    if op == "const" and isinstance(value.get("value"), int):
        return ("const-base", int(value["value"]) & 0xFFFFFFFF)
    args = value.get("args")
    if op in {"add32", "sub32"} and isinstance(args, list) and len(args) == 2:
        left, right = args
        if (
            isinstance(right, Mapping)
            and right.get("op") == "const"
            and isinstance(right.get("value"), int)
        ):
            base = _decompose_address(left)
            if base is not None:
                delta = int(right["value"]) * (1 if op == "add32" else -1)
                return (base[0], (base[1] + delta) & 0xFFFFFFFF)
        if (
            op == "add32"
            and isinstance(left, Mapping)
            and left.get("op") == "const"
            and isinstance(left.get("value"), int)
        ):
            base = _decompose_address(right)
            if base is not None:
                return (base[0], (base[1] + int(left["value"])) & 0xFFFFFFFF)
    return (_canonical_json(value), 0)


def _is_stack_expression(value: Any) -> bool:
    if isinstance(value, Mapping):
        if value.get("op") == "reg" and str(value.get("name", "")).lower() in {
            "esp",
            "ebp",
            "sp",
            "bp",
        }:
            return True
        return any(_is_stack_expression(item) for item in value.values())
    if isinstance(value, list):
        return any(_is_stack_expression(item) for item in value)
    return False


def _expression_occurrences(unit: Mapping[str, Any]) -> Iterable[tuple[dict[str, Any], str]]:
    semantics = unit.get("semantics")
    if not isinstance(semantics, Mapping):
        return

    def visit(value: Any, pointer: str) -> Iterable[tuple[dict[str, Any], str]]:
        if isinstance(value, dict):
            if isinstance(value.get("op"), str):
                yield value, pointer
            for key in sorted(value):
                yield from visit(value[key], pointer + "/" + _pointer_escape(str(key)))
        elif isinstance(value, list):
            for index, item in enumerate(value):
                yield from visit(item, pointer + f"/{index}")

    # pre_state declares the whole architectural state; it is not evidence that
    # every register is an input to this component. Instruction replay likewise
    # duplicates the normalized effects below.
    for field in (
        "edge_conditions",
        "external_events",
        "faults",
        "flag_writes",
        "memory_events",
        "ordered_events",
        "outcome",
        "register_writes",
        "x87_micro_ops",
    ):
        if field in semantics:
            yield from visit(semantics[field], f"/semantics/{field}")


def _named_entries(
    spec: Mapping[str, Any], field: str, issues: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    raw = spec.get(field, [])
    if not isinstance(raw, list):
        _issue(
            issues,
            "violated",
            "malformed_interface_family",
            f"/{field}",
            expected="array",
            observed=raw,
            remediation=f"replace {field} with an array of structured declarations",
        )
        return []
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, item in enumerate(raw):
        if not isinstance(item, dict) or not isinstance(item.get("id"), str) or not item["id"]:
            _issue(
                issues,
                "violated",
                "malformed_interface_entry",
                f"/{field}/{index}",
                expected="object with a non-empty id",
                observed=item,
                remediation="add a stable logical identifier",
            )
            continue
        if item["id"] in seen:
            _issue(
                issues,
                "violated",
                "duplicate_interface_id",
                f"/{field}/{index}/id",
                expected="unique ID within interface family",
                observed=item["id"],
                remediation="rename or merge the duplicate declaration",
            )
        seen.add(item["id"])
        result.append(item)
    return result


def _member_ids(
    component: Mapping[str, Any],
    machine: Mapping[str, Any],
    issues: list[dict[str, Any]],
) -> list[str]:
    membership = component.get("membership")
    raw = membership.get("resolved_unit_ids") if isinstance(membership, Mapping) else None
    if not isinstance(raw, list) or not raw:
        _issue(
            issues,
            "violated",
            "missing_component_membership",
            "/component_id",
            expected="non-empty resolved_unit_ids",
            observed=raw,
            remediation="regenerate the semantic component catalog",
        )
        return []
    result = []
    for unit_id in raw:
        if not isinstance(unit_id, str) or unit_id not in machine["units_by_id"]:
            _issue(
                issues,
                "violated",
                "unknown_component_member",
                "/component_id",
                unit_id=unit_id if isinstance(unit_id, str) else None,
                expected="machine IR unit",
                observed=unit_id,
                remediation="regenerate the semantic component catalog",
            )
        else:
            result.append(unit_id)
    return sorted(set(result), key=lambda value: (_unit_rva(machine["units_by_id"][value]), value))


def _find_component(catalog: Mapping[str, Any], component_id: str) -> dict[str, Any]:
    components = catalog.get("components")
    if not isinstance(components, list):
        raise ComponentInterfaceError("semantic component catalog has no component array")
    matches = [
        item
        for item in components
        if isinstance(item, dict) and item.get("id") == component_id
    ]
    if len(matches) != 1:
        raise ComponentInterfaceError(f"component {component_id!r} is not unique in the catalog")
    return matches[0]


def _add_owner(
    owners: dict[str, list[dict[str, str]]],
    key: str,
    kind: str,
    identity: str,
    location: str,
) -> None:
    owners[key].append({"kind": kind, "id": identity, "json_location": location})


def _effect_key(reference: Mapping[str, Any]) -> str:
    family = str(reference.get("family"))
    unit_id = str(reference.get("unit_id"))
    suffix = f":{reference.get('index')}" if "index" in reference else ""
    return f"{family}:{unit_id}{suffix}"


def _effect_remediation(family: str) -> str:
    return {
        "memory_event": "bind the effect to a checked object field or eligible stack adapter",
        "external_event": "bind the event to a checked service or eligible internal-call frame",
        "control_exit": "add an exact structured control result",
        "fault": "add a structured fault result",
        "register_write": "bind the output result or declare machine-register adapter projection",
        "flag_write": "bind the output result or declare machine-flag adapter projection",
    }.get(family, "represent this effect explicitly")


def _issue(
    issues: list[dict[str, Any]],
    status: str,
    code: str,
    json_location: str,
    *,
    unit_id: str | None = None,
    rva: int | None = None,
    expected: Any = None,
    observed: Any = None,
    remediation: str,
) -> None:
    message = code.replace("_", " ")
    core = {
        "status": status,
        "code": code,
        "message": message,
        "json_location": json_location,
        "unit_id": unit_id,
        "rva": rva,
        "expected": copy.deepcopy(expected),
        "observed": copy.deepcopy(observed),
        "remediation": remediation,
    }
    issues.append(
        {"id": "component-interface-issue:" + _canonical_sha256(core)[:20], **core}
    )


def _issue_sort_key(issue: Mapping[str, Any]) -> tuple[Any, ...]:
    return (
        0 if issue.get("status") == "violated" else 1,
        str(issue.get("json_location", "")),
        str(issue.get("unit_id", "")),
        int(issue.get("rva")) if isinstance(issue.get("rva"), int) else -1,
        str(issue.get("code", "")),
        str(issue.get("id", "")),
    )


def _json_pointer(value: Any, pointer: str) -> Any:
    if pointer == "":
        return value
    if not pointer.startswith("/"):
        raise ValueError("JSON pointer must start with slash")
    current = value
    for encoded in pointer[1:].split("/"):
        token = encoded.replace("~1", "/").replace("~0", "~")
        if isinstance(current, Mapping):
            current = current[token]
        elif isinstance(current, list):
            current = current[int(token)]
        else:
            raise TypeError("JSON pointer traversed a scalar")
    return copy.deepcopy(current)


def _pointer_escape(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def _unit_rva(unit: Mapping[str, Any]) -> int:
    try:
        return int(unit["source"]["original"]["rva_start"])
    except (KeyError, TypeError, ValueError) as error:
        raise ComponentInterfaceError("machine IR unit has no original RVA") from error


def _load_json_input(
    value: Path | str | Mapping[str, Any], label: str
) -> dict[str, Any]:
    if isinstance(value, Mapping):
        result = _json_copy(value, label)
        if not isinstance(result, dict):
            raise ComponentInterfaceError(f"{label} must be an object")
        return result
    return _json_file(Path(value), label)


def _input_artifact_sha256(
    source: Path | str | Mapping[str, Any], payload: Mapping[str, Any]
) -> str:
    if isinstance(source, Mapping):
        return _canonical_sha256(payload)
    return sha256_file(Path(source))


def _json_file(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ComponentInterfaceError(f"cannot read {label} {path}: {error}") from error
    if not isinstance(value, dict):
        raise ComponentInterfaceError(f"{label} must be a JSON object")
    return value


def _json_copy(value: Any, label: str) -> Any:
    try:
        return json.loads(json.dumps(value))
    except (TypeError, ValueError) as error:
        raise ComponentInterfaceError(f"{label} must contain JSON values") from error


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _canonical_sha256(value: Any) -> str:
    return sha256(_canonical_json(value).encode("utf-8")).hexdigest()

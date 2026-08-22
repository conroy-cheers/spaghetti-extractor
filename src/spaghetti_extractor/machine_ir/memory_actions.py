"""Concurrency-preserving memory actions for Machine IR v3.

``memory_events`` described sequential loads and stores.  That representation
cannot distinguish a locked read-modify-write from two ordinary accesses, so it
is retained only as provenance in v3.  This module builds and validates the
authoritative action graph used by qualification and native lowering.
"""

from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Mapping, Sequence
from typing import Any

from ..artifacts.formats import (
    CONCURRENCY_SIGNATURE_FORMAT,
    MACHINE_IR_V2_FORMAT,
    MACHINE_MEMORY_ACTION_GRAPH_FORMAT,
    MEMORY_MODEL_RECEIPT_FORMAT,
    PE32_WB_TSO_PROFILE_ID,
)


ARCHSEM_CONCURRENCY_COMMIT = "dccdcdaeb1fb44d11a5e9ac0b0a9f4391620e453"
ARCHSEM_X86_MODEL_PATH = "ArchSemX86/AxiomaticX86TSO.v"
HERD_X86_MODEL_PATH = "herd/models/x86tso-mixed.cat"

ATOMIC_OPERATIONS = {
    "adc": "add_with_carry",
    "add": "add",
    "and": "bitwise_and",
    "btc": "bit_test_complement",
    "btr": "bit_test_reset",
    "bts": "bit_test_set",
    "cmpxchg": "compare_exchange",
    "cmpxchg8b": "compare_exchange_double_word",
    "dec": "decrement",
    "inc": "increment",
    "neg": "negate",
    "not": "bitwise_not",
    "or": "bitwise_or",
    "sbb": "subtract_with_borrow",
    "sub": "subtract",
    "xadd": "exchange_add",
    "xchg": "exchange",
    "xor": "bitwise_xor",
}

_ACTION_KINDS = frozenset({"read", "write", "rmw", "fence"})
_PE32_WIDTHS = frozenset({1, 2, 4, 8})


class MemoryActionError(ValueError):
    """A memory action graph is malformed or outside the checked profile."""


def memory_model_receipt() -> dict[str, Any]:
    """Return the immutable semantic dependency receipt for this profile."""

    core = {
        "format": MEMORY_MODEL_RECEIPT_FORMAT,
        "profile_id": PE32_WB_TSO_PROFILE_ID,
        "scope": {
            "architecture": "x86",
            "execution_mode": "pe32-user",
            "memory_type": "write_back",
            "memory_model": "tso",
            "naturally_aligned_only": True,
            "thread_lifecycle": "external_frontier",
            "unsupported": [
                "device_or_mmio_memory",
                "non_write_back_memory",
                "split_lock",
                "page_crossing_locked_access",
                "unaligned_atomic_access",
            ],
        },
        "archsem": {
            "commit": ARCHSEM_CONCURRENCY_COMMIT,
            "axiomatic_model": ARCHSEM_X86_MODEL_PATH,
            "integration": "predecoded_event_bridge",
            "decoder": "spaghetti-extractor-xed-validated-pe32",
        },
        "differential_oracle": {
            "implementation": "herdtools7",
            "model": HERD_X86_MODEL_PATH,
            "authority": False,
        },
    }
    return {**core, "receipt_sha256": _sha256(core)}


def build_memory_action_graph(
    *,
    instructions: Sequence[Mapping[str, Any]],
    memory_events: Sequence[Mapping[str, Any]],
    ordered_events: Sequence[Mapping[str, Any]] = (),
    legacy_source: bool = False,
) -> dict[str, Any]:
    """Build a deterministic action graph from checked instruction effects.

    The conversion may inspect v2 memory events, but only a graph built while
    preparing a v3 unit is authoritative.  Atomic instructions must bind to one
    exact read and one exact write.  Failed compare/exchange therefore still has
    one architectural write action; only the value written is conditional.
    """

    events = [_copy_mapping(event, "memory event") for event in memory_events]
    instruction_rows = [
        _copy_mapping(instruction, "instruction") for instruction in instructions
    ]
    event_rvas = _event_instruction_rvas(events, ordered_events)
    issues: list[dict[str, Any]] = []
    claimed: set[int] = set()
    actions_by_position: list[tuple[int, dict[str, Any]]] = []

    for instruction_index, instruction in enumerate(instruction_rows):
        mnemonic = _base_mnemonic(instruction)
        explicit_lock = _has_lock_prefix(instruction)
        implicit_lock = mnemonic == "xchg" and _memory_operands(instruction)
        if not explicit_lock and not implicit_lock:
            continue
        operation = ATOMIC_OPERATIONS.get(mnemonic)
        if operation is None:
            issues.append(
                _issue(
                    "unsupported_atomic_operation",
                    instruction_index=instruction_index,
                    mnemonic=mnemonic,
                )
            )
            continue
        operands = _memory_operands(instruction)
        if len(operands) != 1:
            issues.append(
                _issue(
                    "ambiguous_atomic_target",
                    instruction_index=instruction_index,
                    memory_operands=len(operands),
                )
            )
            continue
        operand = operands[0]
        address = _operand_address(operand)
        width_bits = operand.get("width_bits")
        width = width_bits // 8 if _is_int(width_bits) and width_bits % 8 == 0 else None
        instruction_rva = _instruction_rva(instruction)
        if address is None or width not in _PE32_WIDTHS:
            issues.append(
                _issue(
                    "unsupported_atomic_target",
                    instruction_index=instruction_index,
                    instruction_rva=instruction_rva,
                    width_bytes=width,
                )
            )
            continue
        candidates = [
            index
            for index, event in enumerate(events)
            if index not in claimed
            and event.get("width") == width
            and event.get("kind") in {"read", "write", "read_write"}
            and _canonical(event.get("address")) == _canonical(address)
            and (
                instruction_rva is None
                or event_rvas[index] is None
                or event_rvas[index] == instruction_rva
            )
        ]
        reads = [index for index in candidates if events[index]["kind"] in {"read", "read_write"}]
        writes = [index for index in candidates if events[index]["kind"] in {"write", "read_write"}]
        if len(reads) != 1 or len(writes) != 1:
            issues.append(
                _issue(
                    "ambiguous_atomic_concrete_effects",
                    instruction_index=instruction_index,
                    instruction_rva=instruction_rva,
                    candidate_reads=len(reads),
                    candidate_writes=len(writes),
                )
            )
            continue
        constituent = sorted(set((reads[0], writes[0])))
        claimed.update(constituent)
        domain = _atomic_domain(address, width)
        if domain["status"] != "proved":
            issues.append(
                _issue(
                    "atomic_domain_unproved",
                    instruction_index=instruction_index,
                    instruction_rva=instruction_rva,
                    requirement=domain["requirement"],
                )
            )
        action: dict[str, Any] = {
            "kind": "rmw",
            "instruction_rva": instruction_rva,
            "address": copy.deepcopy(address),
            "width_bytes": width,
            "operation": operation,
            "atomicity": "x86_locked",
            "ordering": "tso_full_barrier",
            "scope": "shared_or_unknown",
            "domain": domain,
            "transition": {
                "observed": {
                    "op": "load",
                    "address": copy.deepcopy(address),
                    "width": width,
                },
                "written": copy.deepcopy(events[writes[0]].get("value")),
                "write_occurs": "always",
            },
            "source_memory_event_indices": constituent,
        }
        if operation == "compare_exchange":
            compare_operands = _compare_exchange_operands(
                written=action["transition"]["written"],
                observed=action["transition"]["observed"],
            )
            if compare_operands is None:
                issues.append(
                    _issue(
                        "compare_exchange_transition_unproved",
                        instruction_index=instruction_index,
                        instruction_rva=instruction_rva,
                    )
                )
                continue
            action["compare"] = {
                "expected": compare_operands[0],
                "desired": compare_operands[1],
                "success_observation": "zf",
            }
        action["id"] = _action_id(action)
        actions_by_position.append((min(constituent), action))

    for index, event in enumerate(events):
        if index in claimed:
            continue
        kind = event.get("kind")
        if kind not in {"read", "write", "read_write"}:
            issues.append(_issue("unsupported_memory_event", event_index=index, kind=kind))
            continue
        if kind == "read_write":
            issues.append(_issue("unclassified_read_write_event", event_index=index))
            continue
        width = event.get("width")
        address = event.get("address")
        if width not in _PE32_WIDTHS or not isinstance(address, Mapping):
            issues.append(_issue("malformed_memory_event", event_index=index))
            continue
        action = {
            "kind": kind,
            "instruction_rva": event_rvas[index],
            "address": copy.deepcopy(address),
            "width_bytes": width,
            "scope": "shared_or_unknown",
            "source_memory_event_indices": [index],
        }
        if kind == "write":
            action["value"] = copy.deepcopy(event.get("value"))
        action["id"] = _action_id(action)
        actions_by_position.append((index, action))

    actions = [item[1] for item in sorted(actions_by_position, key=lambda item: item[0])]
    edges = [
        {"kind": "program_order", "before": left["id"], "after": right["id"]}
        for left, right in zip(actions, actions[1:])
    ]
    authoritative = not legacy_source and not issues
    core: dict[str, Any] = {
        "format": MACHINE_MEMORY_ACTION_GRAPH_FORMAT,
        "profile_id": PE32_WB_TSO_PROFILE_ID,
        "status": "complete" if not issues else "incomplete",
        "authority": {
            "authoritative": authoritative,
            "source": (
                "machine_ir_v2_inspection_adapter"
                if legacy_source
                else "machine_ir_v3_checked_instruction_effects"
            ),
            "reason": (
                "v2 conversion is diagnostic only"
                if legacy_source
                else "all action and domain obligations are satisfied"
                if not issues
                else "one or more action obligations are incomplete"
            ),
        },
        "actions": actions,
        "edges": edges,
        "issues": issues,
        "model_receipt": memory_model_receipt(),
    }
    core["graph_sha256"] = _sha256(core)
    return core


def adapt_v2_memory_action_graph(unit: Mapping[str, Any]) -> dict[str, Any]:
    """Inspect a legacy v2 unit without granting preservation authority."""

    if unit.get("format") != MACHINE_IR_V2_FORMAT:
        raise MemoryActionError("legacy memory-action adapter requires Machine IR v2")
    semantics = unit.get("semantics")
    if not isinstance(semantics, Mapping):
        raise MemoryActionError("legacy Machine IR unit has no semantics")
    instructions = unit.get("instructions")
    memory_events = semantics.get("memory_events")
    ordered_events = semantics.get("ordered_events", [])
    if not isinstance(instructions, list) or not isinstance(memory_events, list):
        raise MemoryActionError("legacy Machine IR memory inventory is malformed")
    if not isinstance(ordered_events, list):
        raise MemoryActionError("legacy Machine IR ordered events are malformed")
    return build_memory_action_graph(
        instructions=instructions,
        memory_events=memory_events,
        ordered_events=ordered_events,
        legacy_source=True,
    )


def validate_memory_action_graph(
    graph: Mapping[str, Any], *, require_authoritative: bool = False
) -> None:
    if graph.get("format") != MACHINE_MEMORY_ACTION_GRAPH_FORMAT:
        raise MemoryActionError("memory action graph has the wrong format")
    if graph.get("profile_id") != PE32_WB_TSO_PROFILE_ID:
        raise MemoryActionError("memory action graph has an unsupported profile")
    actions = graph.get("actions")
    edges = graph.get("edges")
    if not isinstance(actions, list) or not isinstance(edges, list):
        raise MemoryActionError("memory action graph actions and edges must be lists")
    ids: set[str] = set()
    for index, action in enumerate(actions):
        if not isinstance(action, Mapping) or action.get("kind") not in _ACTION_KINDS:
            raise MemoryActionError(f"memory action {index} has an unsupported kind")
        identity = action.get("id")
        if not isinstance(identity, str) or not identity or identity in ids:
            raise MemoryActionError(f"memory action {index} has an invalid id")
        ids.add(identity)
        if action.get("kind") != "fence":
            if action.get("width_bytes") not in _PE32_WIDTHS:
                raise MemoryActionError(f"memory action {identity} has an invalid width")
            if not isinstance(action.get("address"), Mapping):
                raise MemoryActionError(f"memory action {identity} has no address")
        if action.get("kind") == "rmw":
            if action.get("operation") not in set(ATOMIC_OPERATIONS.values()):
                raise MemoryActionError(f"RMW action {identity} has an invalid operation")
            transition = action.get("transition")
            if not isinstance(transition, Mapping) or transition.get("write_occurs") != "always":
                raise MemoryActionError(f"RMW action {identity} must contain one write cycle")
    for edge in edges:
        if (
            not isinstance(edge, Mapping)
            or edge.get("kind") not in {"program_order", "additional_order"}
            or edge.get("before") not in ids
            or edge.get("after") not in ids
        ):
            raise MemoryActionError("memory action graph contains an invalid edge")
    authority = graph.get("authority")
    if require_authoritative and (
        graph.get("status") != "complete"
        or not isinstance(authority, Mapping)
        or authority.get("authoritative") is not True
    ):
        raise MemoryActionError("memory action graph is not authoritative")


def concurrency_signature(
    graph: Mapping[str, Any], *, private_action_ids: Sequence[str] = ()
) -> dict[str, Any]:
    """Create the content-addressed public event graph used for equivalence.

    Private actions may only be erased by supplying explicit proved action ids;
    unclassified memory is conservatively shared.
    """

    validate_memory_action_graph(graph, require_authoritative=True)
    private = set(private_action_ids)
    actions = graph["actions"]
    known = {str(action["id"]) for action in actions}
    if not private <= known:
        raise MemoryActionError("private-memory proof names an unknown action")
    public_actions = [
        _signature_action(action) for action in actions if action["id"] not in private
    ]
    public_ids = {action["id"] for action in public_actions}
    public_edges = [
        {
            "kind": "program_order",
            "before": left["id"],
            "after": right["id"],
        }
        for left, right in zip(public_actions, public_actions[1:])
    ]
    public_edges.extend(
        copy.deepcopy(edge)
        for edge in graph["edges"]
        if edge.get("kind") != "program_order"
        and edge["before"] in public_ids
        and edge["after"] in public_ids
    )
    core = {
        "format": CONCURRENCY_SIGNATURE_FORMAT,
        "profile_id": PE32_WB_TSO_PROFILE_ID,
        "equivalence": "labeled_event_graph_isomorphism",
        "private_memory_erasure": {
            "proof_required": True,
            "erased_action_ids": sorted(private),
            "unknown_memory_classification": "shared",
        },
        "actions": public_actions,
        "edges": public_edges,
        "model_receipt_sha256": graph["model_receipt"]["receipt_sha256"],
    }
    return {**core, "signature_sha256": _sha256(core)}


def signatures_equivalent(left: Mapping[str, Any], right: Mapping[str, Any]) -> bool:
    """Compare canonical labeled event graphs, independent of action ids."""

    return _signature_normal_form(left) == _signature_normal_form(right)


def _signature_normal_form(signature: Mapping[str, Any]) -> str:
    if signature.get("format") != CONCURRENCY_SIGNATURE_FORMAT:
        raise MemoryActionError("concurrency signature has the wrong format")
    actions = signature.get("actions")
    edges = signature.get("edges")
    if not isinstance(actions, list) or not isinstance(edges, list):
        raise MemoryActionError("concurrency signature is malformed")
    labels = {
        str(action.get("id")): _canonical({k: v for k, v in action.items() if k != "id"})
        for action in actions
        if isinstance(action, Mapping)
    }
    if len(labels) != len(actions):
        raise MemoryActionError("concurrency signature contains invalid actions")
    normalized_edges = sorted(
        (str(edge.get("kind")), labels.get(str(edge.get("before"))), labels.get(str(edge.get("after"))))
        for edge in edges
        if isinstance(edge, Mapping)
    )
    return _canonical({"actions": sorted(labels.values()), "edges": normalized_edges})


def _signature_action(action: Mapping[str, Any]) -> dict[str, Any]:
    keep = (
        "id",
        "kind",
        "instruction_rva",
        "address",
        "width_bytes",
        "value",
        "operation",
        "atomicity",
        "ordering",
        "scope",
        "transition",
        "compare",
    )
    return {key: copy.deepcopy(action[key]) for key in keep if key in action}


def _event_instruction_rvas(
    events: Sequence[Mapping[str, Any]], ordered_events: Sequence[Mapping[str, Any]]
) -> list[int | None]:
    ordered = [
        event
        for event in ordered_events
        if isinstance(event, Mapping) and event.get("family") == "memory"
    ]
    if len(ordered) != len(events):
        return [None] * len(events)
    result: list[int | None] = []
    for event, ordered_event in zip(events, ordered, strict=True):
        projected = {key: value for key, value in ordered_event.items() if key not in {"family", "instruction_rva"}}
        if _canonical(projected) != _canonical(event):
            return [None] * len(events)
        value = ordered_event.get("instruction_rva")
        result.append(value if _is_int(value) else None)
    return result


def _atomic_domain(address: Mapping[str, Any], width: int) -> dict[str, Any]:
    constant = _constant_expression_value(address)
    aligned = constant is not None and constant % width == 0
    return {
        "status": "proved" if aligned else "requires_proof",
        "requirement": "naturally_aligned_write_back_non_mmio_non_page_crossing",
        "alignment_bytes": width,
        "constant_address": constant,
        "page_crossing": False if aligned else "unproved",
        "memory_type": "write_back" if aligned else "unproved",
    }


def _constant_expression_value(expression: Mapping[str, Any]) -> int | None:
    if expression.get("op") == "const" and _is_int(expression.get("value")):
        return int(expression["value"])
    return None


def _memory_operands(instruction: Mapping[str, Any]) -> list[dict[str, Any]]:
    operands = instruction.get("operands")
    if not isinstance(operands, list):
        return []
    return [dict(item) for item in operands if isinstance(item, Mapping) and item.get("kind") == "memory"]


def _compare_exchange_operands(
    *, written: Any, observed: Any
) -> tuple[dict[str, Any], dict[str, Any]] | None:
    """Recover CAS inputs from its checked, always-written transition.

    This deliberately uses the aggregate semantic formula rather than decoded
    operands.  Earlier instructions in the same unit may have changed EAX or
    the replacement register before the locked instruction executes.
    """

    if not isinstance(written, Mapping) or written.get("op") != "ite":
        return None
    args = written.get("args")
    if not isinstance(args, list) or len(args) != 3:
        return None
    condition, desired, failure_value = args
    if _canonical(failure_value) != _canonical(observed):
        return None
    if not isinstance(condition, Mapping) or condition.get("op") != "eq":
        return None
    compared = condition.get("args")
    if not isinstance(compared, list) or len(compared) != 2:
        return None
    if _canonical(compared[0]) == _canonical(observed):
        expected = compared[1]
    elif _canonical(compared[1]) == _canonical(observed):
        expected = compared[0]
    else:
        return None
    if not isinstance(expected, Mapping) or not isinstance(desired, Mapping):
        return None
    return copy.deepcopy(dict(expected)), copy.deepcopy(dict(desired))


def _operand_address(operand: Mapping[str, Any]) -> dict[str, Any] | None:
    terms: list[dict[str, Any]] = []
    segment = operand.get("segment")
    if isinstance(segment, str) and segment.lower() in {"fs", "gs"}:
        terms.append({"op": f"{segment.lower()}_base", "width": 32})
    elif segment not in {None, "", "cs", "ds", "es", "ss"}:
        return None
    base = operand.get("base")
    if isinstance(base, str) and base:
        terms.append({"op": "reg", "name": base.lower(), "width": 32})
    index = operand.get("index")
    if isinstance(index, str) and index:
        scale = operand.get("scale", 1)
        if scale not in {1, 2, 4, 8}:
            return None
        term: dict[str, Any] = {"op": "reg", "name": index.lower(), "width": 32}
        if scale != 1:
            term = {"op": "mul32", "args": [term, {"op": "const", "value": scale, "width": 32}]}
        terms.append(term)
    displacement = operand.get("displacement", 0)
    if not _is_int(displacement):
        return None
    if displacement or not terms:
        terms.append({"op": "const", "value": displacement & 0xFFFFFFFF, "width": 32})
    result = terms[0]
    for term in terms[1:]:
        result = {"op": "add32", "args": [result, term]}
    return result


def _has_lock_prefix(instruction: Mapping[str, Any]) -> bool:
    mnemonic = instruction.get("mnemonic")
    if isinstance(mnemonic, str) and mnemonic.strip().lower().startswith("lock "):
        return True
    if instruction.get("lock_prefix") is True:
        return True
    for key in ("prefix", "prefixes"):
        value = instruction.get(key)
        values = [value] if isinstance(value, str) else value
        if isinstance(values, list) and any(
            isinstance(item, str) and item.strip().lower() == "lock" for item in values
        ):
            return True
    attributes = instruction.get("attributes")
    return isinstance(attributes, Mapping) and attributes.get("lock_prefix") is True


def _base_mnemonic(instruction: Mapping[str, Any]) -> str:
    mnemonic = instruction.get("mnemonic")
    if not isinstance(mnemonic, str):
        return ""
    words = mnemonic.strip().lower().split()
    return words[1] if len(words) > 1 and words[0] == "lock" else words[0]


def _instruction_rva(instruction: Mapping[str, Any]) -> int | None:
    value = instruction.get("rva_start", instruction.get("rva"))
    return int(value) if _is_int(value) else None


def _action_id(action: Mapping[str, Any]) -> str:
    return "memory-action:" + _sha256(action)[:20]


def _issue(code: str, **details: Any) -> dict[str, Any]:
    core = {"status": "incomplete", "code": code, **details}
    return {**core, "id": "memory-action-issue:" + _sha256(core)[:20]}


def _copy_mapping(value: Mapping[str, Any], label: str) -> dict[str, Any]:
    try:
        copied = json.loads(json.dumps(value, sort_keys=True))
    except (TypeError, ValueError) as exc:
        raise MemoryActionError(f"{label} is not JSON-compatible") from exc
    if not isinstance(copied, dict):
        raise MemoryActionError(f"{label} must be an object")
    return copied


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


__all__ = [
    "ARCHSEM_CONCURRENCY_COMMIT",
    "ATOMIC_OPERATIONS",
    "MemoryActionError",
    "adapt_v2_memory_action_graph",
    "build_memory_action_graph",
    "concurrency_signature",
    "memory_model_receipt",
    "signatures_equivalent",
    "validate_memory_action_graph",
]

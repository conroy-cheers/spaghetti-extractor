"""Direct callback-frame evidence from transfer-v2 and runtime profiles.

This is the clean-cut replacement for asking the sharded authority-v3 graph to
reconstruct a second copy of callback transport.  The runtime profile declares
the provider callback protocol; transfer-v2 proves an exact non-sentinel value
is passed to that provider.  Root reachability and callback target ownership
remain linked-semantic-module obligations.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3
from ..external.machine_import_profiles import load_machine_import_profile_set
from ..transfer.model import _Call, _Node, _Transfer
from .evidence import MachineCallEvidenceV1
from .frame import PhysicalCallFrameV2


def _mask(value: int) -> int:
    return value & 0xFFFF_FFFF


def _address_key(
    nodes: tuple[_Node, ...], node_id: int, active: frozenset[int] = frozenset()
) -> tuple[object, ...] | None:
    if node_id in active or not 0 <= node_id < len(nodes):
        return None
    node = nodes[node_id]
    nested = active | {node_id}
    if node.op == "const":
        return ("const", _mask(node.immediate))
    if node.op == "reg":
        return ("reg", node.aux, node.immediate)
    if node.op in {"add32", "sub32"}:
        arguments = tuple(
            _address_key(nodes, item, nested) for item in node.args
        )
        if any(item is None for item in arguments):
            return None
        if node.op == "add32":
            nonzero = tuple(
                item for item in arguments if item != ("const", 0)
            )
            if len(nonzero) == 1:
                return nonzero[0]
            return (node.op, *sorted(nonzero, key=repr))
        return (node.op, *arguments)
    return None


def _constant_word(
    nodes: tuple[_Node, ...],
    node_id: int,
    memory: Mapping[tuple[tuple[object, ...], int], int],
    active: frozenset[int] = frozenset(),
) -> int | None:
    if node_id in active or not 0 <= node_id < len(nodes):
        return None
    node = nodes[node_id]
    nested = active | {node_id}
    if node.op == "const":
        return _mask(node.immediate)
    if node.op == "load":
        if len(node.args) != 1:
            return None
        address = _address_key(nodes, node.args[0])
        if address is None:
            return None
        return memory.get((address, node.aux))
    values = tuple(
        _constant_word(nodes, item, memory, nested) for item in node.args
    )
    if any(item is None for item in values):
        return None
    words = tuple(int(item) for item in values)
    if node.op == "add32":
        return _mask(sum(words))
    if node.op == "sub32" and len(words) == 2:
        return _mask(words[0] - words[1])
    if node.op == "and32":
        result = 0xFFFF_FFFF
        for item in words:
            result &= item
        return _mask(result)
    if node.op == "or32":
        result = 0
        for item in words:
            result |= item
        return _mask(result)
    if node.op == "xor32":
        result = 0
        for item in words:
            result ^= item
        return _mask(result)
    if node.op == "not32" and len(words) == 1:
        return _mask(~words[0])
    if node.op == "neg32" and len(words) == 1:
        return _mask(-words[0])
    if node.op == "ite" and len(words) == 3:
        return words[1] if words[0] else words[2]
    return None


def _callback_argument_node(call: _Call, argument_index: int) -> int | None:
    if argument_index < len(call.argument_nodes):
        return call.argument_nodes[argument_index]
    expected_offset = argument_index * 4
    matches = [
        node_id
        for offset, width, node_id in call.stack_inputs
        if offset == expected_offset and width == 4
    ]
    return matches[0] if len(matches) == 1 else None


def _call_value(
    transfer: _Transfer, *, call: _Call, argument_index: int
) -> int | None:
    argument_node = _callback_argument_node(call, argument_index)
    if argument_node is None:
        return None
    memory: dict[tuple[tuple[object, ...], int], int] = {}
    for action in transfer.actions:
        if action.op == "memory_write":
            if len(action.args) != 2:
                memory.clear()
                continue
            address = _address_key(transfer.nodes, action.args[0])
            value = _constant_word(
                transfer.nodes, action.args[1], memory
            )
            if address is None or value is None:
                # An unknown earlier store might alias a value recovered below.
                memory.clear()
            else:
                memory[(address, action.aux)] = value
        elif action.op == "call" and action.aux == call.call_index:
            return _constant_word(transfer.nodes, argument_node, memory)
    return None


def derive_transfer_callback_evidence_v1(
    *,
    frame: PhysicalCallFrameV2,
    transfer_plan: Mapping[str, Any],
    transfers: Sequence[_Transfer],
    runtime_profile_packs: Sequence[Path],
) -> tuple[MachineCallEvidenceV1 | None, dict[str, Any]]:
    """Derive one callback-frame observation without the authority-v3 DAG."""

    profile_set = load_machine_import_profile_set(runtime_profile_packs)
    occurrences: list[dict[str, Any]] = []
    profile_bindings: set[tuple[str, str]] = set()
    selected_protocol: Mapping[str, object] | None = None
    for transfer in transfers:
        for call in transfer.calls:
            if call.kind != "external_call" or call.dll is None:
                continue
            selected = next(
                (
                    item
                    for item in profile_set.contracts
                    if item.identity.dll == call.dll.lower()
                    and (
                        (
                            item.identity.kind == "symbol"
                            and call.symbol == item.identity.value
                        )
                        or (
                            item.identity.kind == "ordinal"
                            and call.ordinal == item.identity.value
                        )
                    )
                ),
                None,
            )
            if selected is None:
                continue
            protocol = selected.contract.get("callback_protocol")
            if (
                not isinstance(protocol, Mapping)
                or protocol.get("id") != frame.subject.identity
            ):
                continue
            source = protocol.get("source")
            if (
                not isinstance(source, Mapping)
                or source.get("kind") != "argument_word"
                or not isinstance(source.get("argument"), int)
            ):
                continue
            value = _call_value(
                transfer,
                call=call,
                argument_index=int(source["argument"]),
            )
            sentinels = source.get("sentinels")
            if (
                value is None
                or not isinstance(sentinels, list)
                or any(
                    not isinstance(item, Mapping)
                    or not isinstance(item.get("word"), int)
                    for item in sentinels
                )
                or value in {int(item["word"]) for item in sentinels}
            ):
                continue
            if selected_protocol is not None and protocol != selected_protocol:
                return None, {
                    "kind": "transfer-v2-callback-binding",
                    "status": "violated",
                    "blocker": "conflicting_callback_protocols",
                    "occurrences": [],
                }
            selected_protocol = protocol
            profile_bindings.add((selected.profile_id, selected.profile_sha256))
            occurrences.append({
                "transfer_id": transfer.identity,
                "call_id": call.call_index,
                "instruction_rva": call.instruction_rva,
                "callback_word": value,
                "profile_id": selected.profile_id,
                "profile_sha256": selected.profile_sha256,
            })
    core: dict[str, Any] = {
        "kind": "transfer-v2-callback-binding",
        "status": "complete" if occurrences else "incomplete",
        "protocol_id": frame.subject.identity,
        "plan_sha256": transfer_plan.get("plan_sha256"),
        "pe_sha256": transfer_plan.get("bindings", {}).get("pe_sha256"),
        "profile_bindings": [
            {"profile_id": identity, "sha256": sha256}
            for identity, sha256 in sorted(profile_bindings)
        ],
        "occurrences": sorted(
            occurrences,
            key=lambda item: (
                item["instruction_rva"], item["transfer_id"], item["call_id"]
            ),
        ),
        "blocker": None if occurrences else "exact_callback_binding_unresolved",
    }
    binding_id = f"transfer-callback-binding-v1:{canonical_sha256_v3(core)}"
    binding = {**core, "id": binding_id}
    pe_sha256 = core["pe_sha256"]
    if (
        not occurrences
        or selected_protocol is None
        or not isinstance(pe_sha256, str)
    ):
        return None, binding
    evidence = MachineCallEvidenceV1.from_transfer_callback_binding(
        frame,
        protocol=selected_protocol,
        binary_sha256=pe_sha256,
        binding_id=binding_id,
        dependency_ids=tuple(
            item["transfer_id"] for item in binding["occurrences"]
        ),
    )
    return evidence, binding


__all__ = ["derive_transfer_callback_evidence_v1"]

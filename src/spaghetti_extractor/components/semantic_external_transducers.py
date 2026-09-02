"""Checked logical-to-physical transducers for component external services."""

from __future__ import annotations

import json
from typing import Mapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3
from .finite_word_transducers import FiniteWordMapError, parse_finite_word_map
from .local_cell_transducers import (
    LocalCellTransducerError,
    checked_initial_words,
    checked_local_cell_selection,
)
from .machine_binding import MachineProjectionV1


class ComponentSemanticContractError(ValueError):
    """A semantic-contract input is malformed or contradicts exact inputs."""


def checked_external_argument_words(contract: Mapping[str, object]) -> int:
    value = contract.get("argument_words")
    if value is None:
        arity = _object(contract.get("arity"), "resolved import arity")
        if arity.get("kind") != "fixed":
            raise ComponentSemanticContractError(
                "external-call contract has no fixed arity"
            )
        value = arity.get("words")
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ComponentSemanticContractError("external-call argument count is invalid")
    return value


def checked_external_contract_id(
    contract: Mapping[str, object],
    payload: Mapping[str, object],
) -> str:
    """Return the checked contract's stable logical identity."""

    identity = payload.get("id")
    if isinstance(identity, str) and identity:
        return identity
    return f"machine-import-contract:{canonical_sha256_v3(dict(contract))}"


def checked_captured_external_target_guard(
    value: object,
    *,
    machine_event: Mapping[str, object],
) -> dict[str, object]:
    """Bind an indirect machine target to one explicit entry-state capability.

    The external identity and physical frame still come from the resolved
    environment's ordinary machine-import contract.  This projection only
    proves where the already loader-authorized target word enters a contextual
    component slice; it does not create another code-capability catalog.
    """

    projection = MachineProjectionV1.parse(value, "captured external target projection")
    if (
        projection.kind not in {"register", "stack"}
        or projection.payload.get("width") != 32
        or projection.payload.get("at") != "entry"
        or machine_event.get("kind") != "indirect_call"
    ):
        raise ComponentSemanticContractError(
            "captured external target is not a 32-bit entry capability"
        )
    target = _object(machine_event.get("target"), "captured external machine target")
    return {
        "op": "eq",
        "args": [
            json.loads(json.dumps(target)),
            {
                "op": "entry_projection",
                "projection": projection.to_payload(),
            },
        ],
    }


def checked_external_stack_arguments(
    stack_inputs: Sequence[Mapping[str, object]],
    *,
    argument_words: int,
) -> list[dict[str, object]]:
    """Materialize a complete checked IA-32 stack-call argument frame.

    Transfer ``stack_inputs`` deliberately records only stack words written by
    the transfer containing the call. An earlier transfer may have staged
    another argument. A fixed-arity checked cdecl/stdcall contract gives the
    complete physical frame, so refinement reads every argument from call-time
    ESP while requiring the sparse transfer inventory to be an exact,
    nonduplicated subset of that frame.
    """

    offsets: set[int] = set()
    for row in stack_inputs:
        offset = row.get("offset")
        width = row.get("width")
        if (
            not isinstance(offset, int)
            or isinstance(offset, bool)
            or offset < 0
            or offset % 4 != 0
            or offset >= argument_words * 4
            or width != 4
            or "value" not in row
            or offset in offsets
        ):
            raise ComponentSemanticContractError(
                "machine external stack inputs contradict the checked ABI frame"
            )
        offsets.add(offset)

    result: list[dict[str, object]] = []
    for index in range(argument_words):
        offset = index * 4
        address: dict[str, object] = {
            "op": "reg",
            "name": "esp",
            "width": 32,
        }
        if offset:
            address = {
                "op": "add32",
                "args": [
                    address,
                    {"op": "const", "value": offset, "width": 32},
                ],
            }
        result.append({"op": "load", "address": address, "width": 4})
    return result


def checked_external_argument_transducers(
    value: object,
    *,
    logical: object,
    logical_types: Mapping[str, object],
    contract: Mapping[str, object],
    contract_payload: Mapping[str, object],
    contract_arguments: Sequence[Mapping[str, object]],
) -> tuple[
    list[dict[str, object]],
    list[dict[str, object]],
    list[dict[str, object]],
    list[dict[str, object]],
]:
    """Check one explicit logical-to-physical call-frame transducer.

    The resolved native contract owns the ABI, out-interface relation, and
    success rule. The component binding may only map logical arguments to
    those checked physical positions or supply exact constant words.
    """

    transducers = [
        _object(item, f"external argument transducer {index}")
        for index, item in enumerate(_array(value, "external argument transducers"))
    ]
    if len(transducers) != len(contract_arguments):
        raise ComponentSemanticContractError(
            "external argument transducer inventory disagrees with the checked ABI"
        )
    parameter_type_ids = tuple(getattr(logical, "parameter_type_ids", ()))
    if logical is None:
        raise ComponentSemanticContractError(
            "external argument transducer has no logical service"
        )
    relations = {
        canonical_sha256_v3(dict(relation)): _object(
            relation, "resolved out-interface relation"
        )
        for relation in _array(
            contract_payload.get("out_interface_relations", []),
            "resolved out-interface relations",
        )
    }
    local_cell_relations = {
        canonical_sha256_v3(dict(relation)): _object(
            relation, "resolved local-cell relation"
        )
        for relation in _array(
            contract_payload.get("local_cells", []),
            "resolved local-cell relations",
        )
    }
    profile_sha256 = contract.get("profile_sha256")
    if not isinstance(profile_sha256, str) or not profile_sha256:
        raise ComponentSemanticContractError(
            "external contract lacks its interface profile digest"
        )
    caller_memory = (
        _checked_caller_memory_arguments(
            contract_payload.get("caller_memory_frame"),
            argument_words=len(contract_arguments),
        )
        if any(item.get("kind") == "local_cell" for item in transducers)
        else {}
    )
    by_parameter: dict[int, dict[str, object]] = {}
    local_cell_ids: set[str] = set()
    guards: list[dict[str, object]] = []
    writebacks: list[dict[str, object]] = []
    physical: list[dict[str, object]] = []
    for physical_index, (transducer, machine_argument) in enumerate(
        zip(transducers, contract_arguments, strict=True)
    ):
        kind = transducer.get("kind")
        physical.append(
            {
                "index": physical_index,
                "machine": json.loads(json.dumps(machine_argument)),
                "transducer": json.loads(json.dumps(transducer)),
            }
        )
        if kind == "constant":
            constant = _word(transducer.get("value"), "constant argument")
            guards.append(
                {
                    "op": "eq",
                    "args": [
                        json.loads(json.dumps(machine_argument)),
                        {"op": "const", "value": constant, "width": 32},
                    ],
                }
            )
            continue
        if kind == "local_cell":
            cell_id = transducer.get("cell_id")
            try:
                initial_words = checked_initial_words(
                    transducer.get("initial_words"),
                    context="semantic local cell",
                )
            except LocalCellTransducerError as exc:
                raise ComponentSemanticContractError(str(exc)) from exc
            relation_sha256 = transducer.get("local_cell_relation_sha256")
            relation = (
                None
                if relation_sha256 is None
                else local_cell_relations.get(str(relation_sha256))
            )
            memory = caller_memory.get(physical_index)
            if (
                not isinstance(cell_id, str)
                or not cell_id
                or cell_id in local_cell_ids
                or memory is None
                or memory.get("role") != "caller_memory"
                or memory.get("retention") != "during_call"
                or memory.get("access") not in {"read", "read_write"}
                or memory.get("extent") not in {"fixed_word", "enclosing_object"}
                or (memory.get("extent") == "fixed_word" and len(initial_words) != 1)
            ):
                raise ComponentSemanticContractError(
                    "local-cell transducer contradicts the checked caller-memory frame"
                )
            if relation is None:
                if relation_sha256 is not None or any(
                    word is None for word in initial_words
                ):
                    raise ComponentSemanticContractError(
                        "partial local-cell initialization lacks its checked relation"
                    )
                input_indices = set(range(len(initial_words)))
            else:
                try:
                    selection = checked_local_cell_selection(
                        relation,
                        physical_index=physical_index,
                        initial_words=initial_words,
                        memory=memory,
                        context="semantic local cell",
                    )
                except LocalCellTransducerError as exc:
                    raise ComponentSemanticContractError(str(exc)) from exc
                input_indices = selection.input_word_indices
            local_cell_ids.add(cell_id)
            for word_index, raw_word in enumerate(initial_words):
                if raw_word is None:
                    if word_index in input_indices:
                        raise ComponentSemanticContractError(
                            "local-cell input word is not initialized"
                        )
                    continue
                if isinstance(raw_word, Mapping):
                    word_expression: dict[str, object] = {
                        "op": "entry_projection",
                        "projection": json.loads(json.dumps(raw_word["projection"])),
                    }
                else:
                    word = _word(raw_word, f"local cell {cell_id!r} word {word_index}")
                    word_expression = {
                        "op": "const",
                        "value": word,
                        "width": 32,
                    }
                address = json.loads(json.dumps(machine_argument))
                if word_index:
                    address = {
                        "op": "add32",
                        "args": [
                            address,
                            {
                                "op": "const",
                                "value": word_index * 4,
                                "width": 32,
                            },
                        ],
                    }
                guards.append(
                    {
                        "op": "eq",
                        "args": [
                            {"op": "load", "address": address, "width": 4},
                            word_expression,
                        ],
                    }
                )
            continue
        if kind == "finite_word_map":
            try:
                parameter_index, cases = parse_finite_word_map(
                    transducer,
                    context="semantic finite-word argument transducer",
                )
            except FiniteWordMapError as exc:
                raise ComponentSemanticContractError(str(exc)) from exc
            if parameter_index >= len(parameter_type_ids):
                raise ComponentSemanticContractError(
                    "finite-word argument transducer names an unknown logical parameter"
                )
            if parameter_index in by_parameter:
                raise ComponentSemanticContractError(
                    "external argument transducer maps one logical parameter twice"
                )
            logical_type = logical_types[parameter_type_ids[parameter_index]]
            if getattr(logical_type, "kind", None) not in {"scalar", "enum"}:
                raise ComponentSemanticContractError(
                    "finite-word argument transducer requires a scalar or enum parameter"
                )
            equalities = [
                {
                    "op": "eq",
                    "args": [
                        json.loads(json.dumps(machine_argument)),
                        {
                            "op": "const",
                            "value": case.physical_value,
                            "width": 32,
                        },
                    ],
                }
                for case in cases
            ]
            guard = equalities[-1]
            for equality in reversed(equalities[:-1]):
                guard = {"op": "or", "args": [equality, guard]}
            guards.append(guard)
            decoded: dict[str, object] = {
                "op": "const",
                "value": cases[-1].logical_value,
                "width": 32,
            }
            for case in reversed(cases[:-1]):
                decoded = {
                    "op": "ite",
                    "args": [
                        {
                            "op": "eq",
                            "args": [
                                json.loads(json.dumps(machine_argument)),
                                {
                                    "op": "const",
                                    "value": case.physical_value,
                                    "width": 32,
                                },
                            ],
                        },
                        {
                            "op": "const",
                            "value": case.logical_value,
                            "width": 32,
                        },
                        decoded,
                    ],
                }
            by_parameter[parameter_index] = decoded
            continue
        parameter_index = int(transducer["parameter_index"])
        if parameter_index < 0 or parameter_index >= len(parameter_type_ids):
            raise ComponentSemanticContractError(
                "external argument transducer names an unknown logical parameter"
            )
        if parameter_index in by_parameter:
            raise ComponentSemanticContractError(
                "external argument transducer maps one logical parameter twice"
            )
        logical_type = logical_types[parameter_type_ids[parameter_index]]
        if kind == "logical_argument":
            if getattr(logical_type, "kind", None) == "resource_cell":
                raise ComponentSemanticContractError(
                    "resource cells require an out-interface transducer"
                )
            by_parameter[parameter_index] = json.loads(json.dumps(machine_argument))
            continue
        if (
            kind != "out_interface"
            or getattr(logical_type, "kind", None) != "resource_cell"
        ):
            raise ComponentSemanticContractError(
                "out-interface transducer requires a writable resource parameter"
            )
        relation_sha256 = str(transducer["out_interface_relation_sha256"])
        relation = relations.get(relation_sha256)
        if relation is None or relation.get("argument_index") != physical_index:
            raise ComponentSemanticContractError(
                "out-interface transducer does not bind the checked relation position"
            )
        success_condition = relation.get("success_condition")
        if success_condition != "hresult_succeeded_eax":
            raise ComponentSemanticContractError(
                "out-interface transducer has an unsupported success condition"
            )
        by_parameter[parameter_index] = {
            "op": "const",
            "value": 0,
            "width": 64,
        }
        guards.append(
            {
                "op": "eq",
                "args": [
                    {
                        "op": "load",
                        "address": json.loads(json.dumps(machine_argument)),
                        "width": int(relation.get("write_width", 0)),
                    },
                    {"op": "const", "value": 0, "width": 32},
                ],
            }
        )
        writebacks.append(
            {
                "parameter_index": parameter_index,
                "profile_sha256": profile_sha256,
                "interface_id": str(relation.get("interface_id")),
                "relation_sha256": relation_sha256,
                "nullable": bool(relation.get("nullable")),
                "success_condition": success_condition,
                "projection": {
                    "kind": "resource",
                    "resource_kind": getattr(logical_type, "resource_kind"),
                    "source": {
                        "kind": "memory",
                        "address": {
                            "kind": "stack",
                            "offset": physical_index * 4,
                            "width": 32,
                            "at": "call",
                        },
                        "width": 32,
                        "access": "read_write",
                        "at": "call",
                    },
                },
            }
        )
    if set(by_parameter) != set(range(len(parameter_type_ids))):
        raise ComponentSemanticContractError(
            "external argument transducer does not map every logical parameter"
        )
    return (
        [by_parameter[index] for index in range(len(parameter_type_ids))],
        physical,
        guards,
        writebacks,
    )


def checked_local_cell_result_projection(
    value: object,
    *,
    logical_kind: str,
    transducers: object,
    contract_payload: Mapping[str, object],
    argument_words: int,
) -> tuple[dict[str, object], dict[str, object] | None]:
    """Bind a scalar service result to one fully initialized local cell word."""

    if logical_kind not in {"scalar", "enum"}:
        raise ComponentSemanticContractError(
            "local-cell service results require a scalar or enum logical result"
        )
    row = _object(value, "checked local-cell result projection")
    if (
        set(row) != {"kind", "cell_id", "word_index"}
        or row.get("kind") != "local_cell_word"
    ):
        raise ComponentSemanticContractError(
            "local-cell result projection fields are malformed"
        )
    cell_id = row.get("cell_id")
    word_index = row.get("word_index")
    if (
        not isinstance(cell_id, str)
        or not cell_id
        or not isinstance(word_index, int)
        or isinstance(word_index, bool)
        or word_index < 0
    ):
        raise ComponentSemanticContractError(
            "local-cell result identity or word index is invalid"
        )
    matches = [
        (index, item)
        for index, item in enumerate(
            _array(transducers, "local-cell result argument transducers")
        )
        if isinstance(item, Mapping)
        and item.get("kind") == "local_cell"
        and item.get("cell_id") == cell_id
    ]
    if len(matches) != 1:
        raise ComponentSemanticContractError(
            "local-cell result does not name one checked argument cell"
        )
    physical_index, transducer = matches[0]
    try:
        initial_words = checked_initial_words(
            transducer.get("initial_words"),
            context="local-cell result",
        )
    except LocalCellTransducerError as exc:
        raise ComponentSemanticContractError(str(exc)) from exc
    memory = _checked_caller_memory_arguments(
        contract_payload.get("caller_memory_frame"),
        argument_words=argument_words,
    ).get(physical_index)
    relation_sha256 = transducer.get("local_cell_relation_sha256")
    relation = None
    if relation_sha256 is not None:
        relation = {
            canonical_sha256_v3(dict(item)): _object(item, "local-cell result relation")
            for item in _array(
                contract_payload.get("local_cells", []),
                "local-cell result relations",
            )
        }.get(str(relation_sha256))
    if (
        word_index >= len(initial_words)
        or memory is None
        or memory.get("access") != "read_write"
    ):
        raise ComponentSemanticContractError(
            "local-cell result is outside a checked writable cell"
        )
    result_rule: dict[str, object] | None = None
    if relation is not None:
        try:
            selection = checked_local_cell_selection(
                relation,
                physical_index=physical_index,
                initial_words=initial_words,
                memory=memory,
                context="local-cell result",
            )
        except LocalCellTransducerError as exc:
            raise ComponentSemanticContractError(str(exc)) from exc
        if word_index not in selection.output_word_indices or (
            selection.output_condition != "always"
            and word_index not in selection.failure_preserved_word_indices
            and word_index not in selection.failure_observed_word_indices
        ):
            raise ComponentSemanticContractError(
                "local-cell result is not defined on every call outcome"
            )
        if (
            selection.output_condition == "hresult_succeeded_eax"
            and word_index in selection.failure_preserved_word_indices
        ):
            initial_word = initial_words[word_index]
            if isinstance(initial_word, Mapping):
                failure_value = {
                    "op": "entry_projection",
                    "projection": json.loads(json.dumps(initial_word["projection"])),
                }
            else:
                failure_value = {
                    "op": "const",
                    "value": _word(
                        initial_word,
                        "local-cell failure-preserved initial word",
                    ),
                    "width": 32,
                }
            result_rule = {
                "kind": "hresult_success_or_preserved_initial",
                "relation_sha256": str(relation_sha256),
                "variant_id": selection.variant_id,
                "word_index": word_index,
                "failure_value": failure_value,
            }
    elif relation_sha256 is not None or initial_words[word_index] is None:
        raise ComponentSemanticContractError(
            "local-cell result lacks a total checked relation"
        )
    address: dict[str, object] = {
        "kind": "stack",
        "offset": physical_index * 4,
        "width": 32,
        "at": "call",
    }
    if word_index:
        address = {
            "kind": "offset",
            "base": address,
            "offset_bytes": word_index * 4,
            "at": "call",
        }
    projection = {
        "kind": "memory",
        "address": address,
        "width": 32,
        "access": "read_write",
        "at": "call",
    }
    return (
        MachineProjectionV1.parse(
            projection, "checked local-cell machine result"
        ).to_payload(),
        result_rule,
    )


def checked_external_result_projection(
    value: object,
    *,
    logical_kind: str,
    machine_register: str,
) -> dict[str, object]:
    """Validate an operator wrapper around an authorized ABI result."""

    projection = MachineProjectionV1.parse(value, "checked external result projection")
    expected = {
        "scalar": "register",
        "enum": "register",
        "resource": "resource",
        "callback": "callback_handle",
        "reference": "reference",
        "view": "view",
    }.get(logical_kind)
    if expected is None:
        raise ComponentSemanticContractError(
            f"logical result kind {logical_kind!r} has no external result adapter"
        )
    if projection.kind != expected:
        raise ComponentSemanticContractError(
            f"logical result kind {logical_kind!r} requires {expected!r}, "
            f"not {projection.kind!r}"
        )
    source = projection
    while source.kind in {"resource", "callback_handle", "reference", "view"}:
        field = "base" if source.kind == "view" else "source"
        source = MachineProjectionV1.parse(
            source.payload.get(field),
            f"checked external {projection.kind} result source",
        )
    if source.kind != "register":
        raise ComponentSemanticContractError(
            "checked external result must wrap a register projection"
        )
    observed_register = source.payload.get("register")
    if observed_register != machine_register:
        raise ComponentSemanticContractError(
            "checked external result register disagrees with its ABI contract"
        )
    if source.payload.get("at") != "call":
        raise ComponentSemanticContractError(
            "checked external result register must be observed at the call"
        )
    return projection.to_payload()


def _object(value: object, context: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ComponentSemanticContractError(f"{context} is not an object")
    return value


def _array(value: object, context: str) -> list[object]:
    if not isinstance(value, list):
        raise ComponentSemanticContractError(f"{context} is not an array")
    return value


def _checked_caller_memory_arguments(
    value: object,
    *,
    argument_words: int,
) -> dict[int, Mapping[str, object]]:
    frame = _object(value, "checked caller-memory frame")
    if frame.get("status") != "complete":
        raise ComponentSemanticContractError(
            "external contract has no complete caller-memory frame"
        )
    result: dict[int, Mapping[str, object]] = {}
    for raw in _array(frame.get("arguments"), "checked caller-memory arguments"):
        row = _object(raw, "checked caller-memory argument")
        index = row.get("argument_index")
        if (
            not isinstance(index, int)
            or isinstance(index, bool)
            or not 0 <= index < argument_words
            or index in result
        ):
            raise ComponentSemanticContractError(
                "checked caller-memory argument inventory is ambiguous"
            )
        result[index] = row
    return result


def _word(value: object, context: str) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not 0 <= value <= 0xFFFFFFFF
    ):
        raise ComponentSemanticContractError(f"{context} does not fit one word")
    return value


__all__ = [
    "ComponentSemanticContractError",
    "checked_external_argument_transducers",
    "checked_external_argument_words",
    "checked_external_contract_id",
    "checked_local_cell_result_projection",
    "checked_external_result_projection",
    "checked_external_stack_arguments",
]

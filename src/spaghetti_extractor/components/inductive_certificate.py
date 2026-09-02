"""Derive induction certificates from exact machine artifacts and invariants.

Operators provide only machine-free invariants and ranking expressions.  SCCs,
segments, guards, updates, completions, hashes, and evidence dependencies are
materialized from checked artifacts, preventing handwritten inventories from
drifting away from the machine semantics they describe.
"""

from __future__ import annotations

import copy
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from ..artifacts.artifact_set import canonical_sha256_v3
from ..util import write_json
from .inductive_contract import (
    ExpressionV1,
    InductiveOperationCertificateV1,
    check_inductive_operation_certificate,
)
from .inductive_receipts import (
    CheckedInductiveMachineReceiptV1,
    CheckedInductiveSourceReceiptV1,
)
from .inductive_package import INDUCTIVE_COMPONENT_DECLARATION_V1
from .inductive_relation import InductiveCutpointRelationV1
from .inductive_source import InductiveSourcePlanV1
from .interface_ir import ProofKernelLogicalType, ProofKernelComponentInterface
from .semantic_contract import ProofKernelSemanticContract
from .semantic_paths import build_inductive_segment_models
from .source import load_component_source_package


INDUCTIVE_PROOF_DECLARATION_V1 = (
    "spaghetti-extractor-inductive-proof-declaration-v1"
)

_ID = re.compile(r"[A-Za-z_][A-Za-z0-9_.:-]{0,255}\Z")


class InductiveCertificateError(ValueError):
    """A proof declaration cannot describe the exact induction problem."""


def _object(value: object, fields: set[str], context: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise InductiveCertificateError(
            f"{context} must contain exactly {sorted(fields)!r}"
        )
    return value


def _mapping(value: object, context: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise InductiveCertificateError(f"{context} must be an object")
    return value


def _rows(value: object, context: str) -> list[Mapping[str, object]]:
    if not isinstance(value, list) or any(not isinstance(item, Mapping) for item in value):
        raise InductiveCertificateError(f"{context} must be an array of objects")
    return list(value)


def _identifier(value: object, context: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise InductiveCertificateError(f"{context} is not a canonical identifier")
    return value


@dataclass(frozen=True)
class InvariantDeclarationV1:
    identity: str
    owner_cutpoint_id: str
    expression: ExpressionV1

    @classmethod
    def parse(cls, value: object, context: str) -> "InvariantDeclarationV1":
        row = _object(value, {"id", "owner_cutpoint_id", "expression"}, context)
        expression = ExpressionV1.parse(row["expression"], f"{context} expression")
        if expression.result_sort() != "bool" or expression.sort_errors():
            raise InductiveCertificateError(f"{context} is not a well-sorted predicate")
        return cls(
            _identifier(row["id"], f"{context} id"),
            _identifier(row["owner_cutpoint_id"], f"{context} owner"),
            expression,
        )


@dataclass(frozen=True)
class MeasureDeclarationV1:
    identity: str
    owner_cutpoint_id: str
    variable_id: str
    expression: ExpressionV1

    @classmethod
    def parse(cls, value: object, context: str) -> "MeasureDeclarationV1":
        row = _object(
            value,
            {"id", "owner_cutpoint_id", "variable_id", "expression"},
            context,
        )
        expression = ExpressionV1.parse(row["expression"], f"{context} expression")
        if expression.result_sort() != "word" or expression.sort_errors():
            raise InductiveCertificateError(f"{context} is not a scalar expression")
        return cls(
            _identifier(row["id"], f"{context} id"),
            _identifier(row["owner_cutpoint_id"], f"{context} owner"),
            _identifier(row["variable_id"], f"{context} variable"),
            expression,
        )


@dataclass(frozen=True)
class InductiveProofDeclarationV1:
    invariants: tuple[InvariantDeclarationV1, ...]
    measures: tuple[MeasureDeclarationV1, ...]
    declaration_sha256: str

    @classmethod
    def parse(cls, value: object) -> "InductiveProofDeclarationV1":
        if isinstance(value, Mapping) and value.get("format") == INDUCTIVE_COMPONENT_DECLARATION_V1:
            combined = _object(
                value,
                {"format", "source", "proof"},
                "inductive component declaration",
            )
            proof = _mapping(combined["proof"], "inductive proof declaration")
            return cls.parse(
                {"format": INDUCTIVE_PROOF_DECLARATION_V1, **proof}
            )
        row = _object(
            value,
            {"format", "invariants", "measures"},
            "inductive proof declaration",
        )
        if row["format"] != INDUCTIVE_PROOF_DECLARATION_V1:
            raise InductiveCertificateError(
                "unsupported inductive proof declaration format"
            )
        invariants = tuple(
            InvariantDeclarationV1.parse(item, f"invariant {index}")
            for index, item in enumerate(_rows(row["invariants"], "invariants"))
        )
        measures = tuple(
            MeasureDeclarationV1.parse(item, f"measure {index}")
            for index, item in enumerate(_rows(row["measures"], "measures"))
        )
        for name, values in (("invariants", invariants), ("measures", measures)):
            identities = [item.identity for item in values]
            if not values or identities != sorted(identities) or len(identities) != len(set(identities)):
                raise InductiveCertificateError(
                    f"{name} must be nonempty, ordered, and unique"
                )
        return cls(
            invariants,
            measures,
            canonical_sha256_v3(json.loads(json.dumps(row))),
        )


def materialize_inductive_certificate(
    *,
    proof_declaration: Path | str | Mapping[str, object],
    semantic_contract: Path | str | Mapping[str, object],
    interface: Path | str | Mapping[str, object],
    source_package: Path | str,
    source_plan: Path | str | Mapping[str, object] | InductiveSourcePlanV1,
    machine_receipt: Path | str | Mapping[str, object] | CheckedInductiveMachineReceiptV1,
    cutpoint_relation: Path | str | Mapping[str, object] | InductiveCutpointRelationV1,
    service_bindings: object | None = None,
    source_receipt: Path | str | Mapping[str, object] | CheckedInductiveSourceReceiptV1 | None = None,
) -> InductiveOperationCertificateV1:
    """Build a draft or final certificate without accepting machine inventory."""

    proof = InductiveProofDeclarationV1.parse(
        _load(proof_declaration, "inductive proof declaration")
    )
    portable = ProofKernelComponentInterface.parse(
        _load(interface, "portable component interface")
    )
    semantic = ProofKernelSemanticContract.parse(
        _load(semantic_contract, "component semantic contract")
    )
    if semantic.status != "satisfied":
        raise InductiveCertificateError(
            "inductive certificate requires a satisfied semantic contract"
        )
    plan = (
        source_plan
        if isinstance(source_plan, InductiveSourcePlanV1)
        else InductiveSourcePlanV1.parse(_load(source_plan, "inductive source plan"))
    )
    relation = (
        cutpoint_relation
        if isinstance(cutpoint_relation, InductiveCutpointRelationV1)
        else InductiveCutpointRelationV1.parse(
            _load(cutpoint_relation, "inductive cutpoint relation")
        )
    )
    semantic_payload = semantic.to_payload()
    operations = [
        item
        for item in _rows(semantic_payload["operations"], "semantic operations")
        if item.get("operation_id") == plan.operation_id
    ]
    if len(operations) != 1:
        raise InductiveCertificateError("inductive semantic operation is ambiguous")
    operation = operations[0]
    machine = (
        machine_receipt
        if isinstance(machine_receipt, CheckedInductiveMachineReceiptV1)
        else CheckedInductiveMachineReceiptV1.parse(
            _load(machine_receipt, "inductive machine receipt"),
            exact_operation=operation,
        )
    )
    relation.validate_for(portable, plan, machine)
    if machine.semantic_contract_sha256 != semantic.contract_sha256:
        raise InductiveCertificateError(
            "machine receipt is bound to a different semantic contract"
        )
    source = load_component_source_package(source_package)
    final_source = _load_source_receipt(source_receipt)
    if final_source is not None and (
        final_source.component_id != source["lift_unit_id"]
        or final_source.interface_sha256 != portable.sha256
        or final_source.source_plan_sha256 != plan.plan_sha256
        or final_source.relation_sha256 != relation.relation_sha256
        or final_source.implementation_sha256 != source["implementation_sha256"]
    ):
        raise InductiveCertificateError(
            "source receipt is bound to different induction artifacts"
        )

    shape = machine.shape.to_value()
    inventory = machine.segment_inventory.to_value()
    assert isinstance(shape, dict) and isinstance(inventory, dict)
    model = build_inductive_segment_models(
        operation,
        portable,
        plan,
        machine,
        relation,
        (
            semantic_payload.get("services", [])
            if service_bindings is None
            else service_bindings
        ),
    )
    model_by_segment = {
        str(item["segment_id"]): item
        for item in _rows(model["segments"], "inductive semantic models")
    }
    inventory_by_segment = {
        str(item["segment_id"]): item
        for item in _rows(inventory["segments"], "inductive segment inventory")
    }

    scc_rows = sorted(
        _rows(shape["cyclic_sccs"], "machine cyclic SCCs"),
        key=lambda item: str(item["scc_id"]),
    )
    cutpoint_owner: dict[str, str] = {}
    scc_members: dict[str, set[str]] = {}
    for raw_scc in scc_rows:
        scc_id = str(raw_scc["scc_id"])
        members = {str(item) for item in raw_scc["member_unit_ids"]}
        scc_members[scc_id] = members
        for cutpoint in relation.cutpoints:
            if cutpoint.unit_id in members:
                previous = cutpoint_owner.setdefault(cutpoint.unit_id, scc_id)
                if previous != scc_id:
                    raise InductiveCertificateError(
                        "one cutpoint belongs to multiple exact SCCs"
                    )
    if set(cutpoint_owner) != {item.unit_id for item in relation.cutpoints}:
        raise InductiveCertificateError(
            "every selected cutpoint must belong to one exact cyclic SCC"
        )

    invariants_by_scc: dict[str, list[InvariantDeclarationV1]] = {
        scc_id: [] for scc_id in scc_members
    }
    for invariant in proof.invariants:
        owner = cutpoint_owner.get(invariant.owner_cutpoint_id)
        if owner is None:
            raise InductiveCertificateError(
                f"invariant {invariant.identity!r} has an unknown cutpoint"
            )
        invariants_by_scc[owner].append(invariant)
    measures_by_scc: dict[str, MeasureDeclarationV1] = {}
    for measure in proof.measures:
        owner = cutpoint_owner.get(measure.owner_cutpoint_id)
        if owner is None or owner in measures_by_scc:
            raise InductiveCertificateError(
                "every exact SCC must have one unambiguous ranking expression"
            )
        measures_by_scc[owner] = measure
    if any(not values for values in invariants_by_scc.values()) or set(measures_by_scc) != set(scc_members):
        raise InductiveCertificateError(
            "every exact cyclic SCC requires local invariants and one ranking expression"
        )

    entry_by_scc: dict[str, set[str]] = {item: set() for item in scc_members}
    direct_entry_sccs: set[str] = set()
    transitions_by_scc: dict[str, list[Mapping[str, object]]] = {
        item: [] for item in scc_members
    }
    bridges_by_scc: dict[str, list[Mapping[str, object]]] = {
        item: [] for item in scc_members
    }
    incoming_bridges_by_scc: dict[str, list[Mapping[str, object]]] = {
        item: [] for item in scc_members
    }
    completions_by_scc: dict[str, list[Mapping[str, object]]] = {
        item: [] for item in scc_members
    }
    for segment in inventory_by_segment.values():
        source_endpoint = _mapping(segment["source"], "segment source")
        target_endpoint = _mapping(segment["target"], "segment target")
        source_kind = str(source_endpoint["kind"])
        target_kind = str(target_endpoint["kind"])
        if source_kind == "operation_entry" and target_kind == "cutpoint":
            target_scc = cutpoint_owner[str(target_endpoint["id"])]
            entry_by_scc[target_scc].add(str(target_endpoint["id"]))
            direct_entry_sccs.add(target_scc)
        elif source_kind == "cutpoint" and target_kind == "cutpoint":
            source_scc = cutpoint_owner[str(source_endpoint["id"])]
            target_scc = cutpoint_owner[str(target_endpoint["id"])]
            if source_scc != target_scc:
                bridges_by_scc[source_scc].append(segment)
                incoming_bridges_by_scc[target_scc].append(segment)
                entry_by_scc[target_scc].add(str(target_endpoint["id"]))
            else:
                transitions_by_scc[source_scc].append(segment)
        elif source_kind == "cutpoint" and target_kind == "operation_exit":
            completions_by_scc[cutpoint_owner[str(source_endpoint["id"])]].append(
                segment
            )
        elif source_kind == "operation_entry" and target_kind == "operation_exit":
            # Acyclic early completion is checked directly by the source
            # initialization harness.  It needs no SCC invariant witness.
            continue
        else:
            raise InductiveCertificateError(
                "exact segment cannot be represented by the current induction certificate"
            )
    if any(not entry_by_scc[item] for item in scc_members):
        raise InductiveCertificateError(
            "each exact SCC requires an operation-entry or checked bridge path"
        )
    if any(not transitions_by_scc[item] for item in scc_members):
        raise InductiveCertificateError(
            "each exact cyclic SCC requires preservation segments"
        )
    if any(
        not bridges_by_scc[item] and not completions_by_scc[item]
        for item in scc_members
    ):
        raise InductiveCertificateError(
            "each exact cyclic SCC requires an outgoing bridge or completion"
        )
    _check_acyclic_bridge_graph(
        scc_members,
        bridges_by_scc,
        cutpoint_owner,
        direct_entry_sccs,
    )

    variables = _derive_variables(portable, plan, relation)
    variable_ids = {str(item["id"]) for item in variables}
    for measure in measures_by_scc.values():
        if measure.variable_id not in variable_ids:
            raise InductiveCertificateError(
                f"ranking witness {measure.identity!r} names an unknown variable"
            )

    machine_sccs: list[dict[str, object]] = []
    predicates: list[dict[str, object]] = []
    initialization: list[dict[str, object]] = []
    preservation: list[dict[str, object]] = []
    bridges: list[dict[str, object]] = []
    decreases: list[dict[str, object]] = []
    exits: list[dict[str, object]] = []
    completions: list[dict[str, object]] = []
    init_ids_by_scc: dict[str, list[str]] = {}
    preserve_ids_by_scc: dict[str, list[str]] = {}
    decrease_ids_by_scc: dict[str, list[str]] = {}
    bridge_ids_by_scc = {
        scc_id: [
            f"bridge:{_short_id(str(segment['segment_id']))}"
            for segment in sorted(
                segments, key=lambda item: str(item["segment_id"])
            )
        ]
        for scc_id, segments in bridges_by_scc.items()
    }
    incoming_bridge_ids_by_scc = {
        scc_id: sorted(
            f"bridge:{_short_id(str(segment['segment_id']))}"
            for segment in segments
        )
        for scc_id, segments in incoming_bridges_by_scc.items()
    }

    for scc_index, raw_scc in enumerate(scc_rows):
        scc_id = str(raw_scc["scc_id"])
        cutpoints = sorted(
            item for item, owner in cutpoint_owner.items() if owner == scc_id
        )
        invariant_ids = sorted(item.identity for item in invariants_by_scc[scc_id])
        predicates.extend(
            {
                "id": item.identity,
                "scc_id": scc_id,
                "kind": "invariant",
                "expression": item.expression.to_payload(),
            }
            for item in invariants_by_scc[scc_id]
        )
        postcondition_id = None
        if completions_by_scc[scc_id]:
            postcondition_id = f"postcondition:{scc_index:04d}:true"
            predicates.append(
                {
                    "id": postcondition_id,
                    "scc_id": scc_id,
                    "kind": "postcondition",
                    "expression": {"op": "true"},
                }
            )

        init_ids: list[str] = []
        direct_entry_cutpoints = {
            str(_mapping(segment["target"], "entry target")["id"])
            for segment in inventory_by_segment.values()
            if _mapping(segment["source"], "entry source").get("kind")
            == "operation_entry"
            and _mapping(segment["target"], "entry target").get("kind")
            == "cutpoint"
            and cutpoint_owner[
                str(_mapping(segment["target"], "entry target")["id"])
            ]
            == scc_id
        }
        for cutpoint in sorted(direct_entry_cutpoints):
            identity = f"initialization:{_short_id(cutpoint)}"
            init_ids.append(identity)
            initialization.append(
                {
                    "id": identity,
                    "scc_id": scc_id,
                    "cutpoint_id": cutpoint,
                    "establishes": invariant_ids,
                    "dependencies": ["proof-declaration"],
                }
            )
        init_ids_by_scc[scc_id] = init_ids

        preserve_ids: list[str] = []
        decrease_ids: list[str] = []
        measure = measures_by_scc[scc_id]
        for segment in transitions_by_scc[scc_id]:
            segment_id = str(segment["segment_id"])
            semantic_segment = model_by_segment[segment_id]
            target_values = _mapping(
                semantic_segment["target_values"], "segment target values"
            )
            updates = [
                {
                    "variable_id": field.identity,
                    "expression": copy.deepcopy(
                        target_values[f"source_state:{field.identity}"]
                    ),
                }
                for field in plan.state
            ]
            preserve_id = f"preservation:{_short_id(segment_id)}"
            decrease_id = f"decrease:{_short_id(segment_id)}"
            preserve_ids.append(preserve_id)
            decrease_ids.append(decrease_id)
            preservation.append(
                {
                    "id": preserve_id,
                    "scc_id": scc_id,
                    "transition_id": segment_id,
                    "source_cutpoint_id": segment["source"]["id"],
                    "target_cutpoint_id": segment["target"]["id"],
                    "machine_unit_ids": sorted(str(item) for item in segment["unit_ids"]),
                    "guard": _combine(
                        "and", _rows(semantic_segment["guards"], "segment guards")
                    ),
                    "updates": sorted(updates, key=lambda item: str(item["variable_id"])),
                    "preserves": invariant_ids,
                    "dependencies": sorted([
                        *init_ids,
                        *incoming_bridge_ids_by_scc[scc_id],
                        "proof-declaration",
                    ]),
                }
            )
            state_updates = {
                str(item["variable_id"]): item["expression"] for item in updates
            }
            decreases.append(
                {
                    "id": decrease_id,
                    "scc_id": scc_id,
                    "transition_id": segment_id,
                    "measure_id": measure.variable_id,
                    "before": measure.expression.to_payload(),
                    "after": _substitute_state(
                        measure.expression.to_payload(), state_updates
                    ),
                    "relation": "unsigned_lt",
                    "dependencies": [preserve_id],
                }
            )
        preserve_ids_by_scc[scc_id] = preserve_ids
        decrease_ids_by_scc[scc_id] = decrease_ids

        for segment in sorted(
            bridges_by_scc[scc_id], key=lambda item: str(item["segment_id"])
        ):
            segment_id = str(segment["segment_id"])
            semantic_segment = model_by_segment[segment_id]
            target_endpoint = _mapping(segment["target"], "bridge target")
            target_scc = cutpoint_owner[str(target_endpoint["id"])]
            target_values = _mapping(
                semantic_segment["target_values"], "bridge target values"
            )
            updates = [
                {
                    "variable_id": field.identity,
                    "expression": copy.deepcopy(
                        target_values[f"source_state:{field.identity}"]
                    ),
                }
                for field in plan.state
            ]
            bridges.append(
                {
                    "id": f"bridge:{_short_id(segment_id)}",
                    "transition_id": segment_id,
                    "source_scc_id": scc_id,
                    "target_scc_id": target_scc,
                    "source_cutpoint_id": segment["source"]["id"],
                    "target_cutpoint_id": target_endpoint["id"],
                    "machine_unit_ids": sorted(
                        str(item) for item in segment["unit_ids"]
                    ),
                    "guard": _combine(
                        "and", _rows(semantic_segment["guards"], "bridge guards")
                    ),
                    "updates": sorted(
                        updates, key=lambda item: str(item["variable_id"])
                    ),
                    "establishes": sorted(
                        item.identity for item in invariants_by_scc[target_scc]
                    ),
                    "dependencies": sorted([
                        *init_ids,
                        *incoming_bridge_ids_by_scc[scc_id],
                        *preserve_ids,
                        "proof-declaration",
                    ]),
                }
            )

        completion_ids: list[str] = []
        completion_segments_by_exit: dict[tuple[str, str], list[Mapping[str, object]]] = {}
        for segment in completions_by_scc[scc_id]:
            semantic_segment = model_by_segment[str(segment["segment_id"])]
            logical_completion = str(
                _mapping(semantic_segment["target"], "completion target")[
                    "completion_id"
                ]
            )
            source_cutpoint = str(segment["source"]["id"])
            completion_segments_by_exit.setdefault(
                (source_cutpoint, logical_completion), []
            ).append(segment)
        exits_by_cutpoint: dict[str, list[str]] = {}
        for (source_cutpoint, logical_completion), segments in sorted(
            completion_segments_by_exit.items()
        ):
            assert postcondition_id is not None
            completion_id = (
                f"completion:{logical_completion}:{_short_id(source_cutpoint)}"
            )
            completion_ids.append(completion_id)
            exits_by_cutpoint.setdefault(source_cutpoint, []).append(completion_id)
            completion_witness_id = f"exit:{_short_id(source_cutpoint)}"
            completions.append(
                {
                    "id": completion_id,
                    "scc_id": scc_id,
                    "exit_witness_id": completion_witness_id,
                    "kind": "return",
                    "machine_unit_ids": sorted(
                        {
                            str(unit_id)
                            for segment in segments
                            for unit_id in segment["unit_ids"]
                        }
                    ),
                    "postcondition_ids": [postcondition_id],
                    "dependencies": [completion_witness_id],
                }
            )
        for source_cutpoint, local_completion_ids in sorted(exits_by_cutpoint.items()):
            matching = [
                segment
                for segment in completions_by_scc[scc_id]
                if str(segment["source"]["id"]) == source_cutpoint
            ]
            exits.append(
                {
                    "id": f"exit:{_short_id(source_cutpoint)}",
                    "scc_id": scc_id,
                    "cutpoint_id": source_cutpoint,
                    "guard": _combine(
                        "or",
                        [
                            _combine(
                                "and",
                                _rows(
                                    model_by_segment[str(segment["segment_id"])][
                                        "guards"
                                    ],
                                    "completion guards",
                                ),
                            )
                            for segment in matching
                        ],
                    ),
                    "establishes": [postcondition_id],
                    "completion_ids": sorted(local_completion_ids),
                    "dependencies": sorted(decrease_ids),
                }
            )

        machine_sccs.append(
            {
                "id": scc_id,
                "unit_ids": sorted(scc_members[scc_id]),
                "cutpoint_ids": cutpoints,
                "entry_cutpoint_ids": sorted(entry_by_scc[scc_id]),
                "exit_cutpoint_ids": sorted(exits_by_cutpoint),
                "transition_ids": sorted(
                    str(item["segment_id"]) for item in transitions_by_scc[scc_id]
                ),
                "bridge_ids": sorted(
                    str(item["segment_id"]) for item in bridges_by_scc[scc_id]
                ),
                "completion_ids": sorted(completion_ids),
            }
        )

    semantic_bindings = _mapping(
        semantic_payload["bindings"], "semantic contract bindings"
    )
    source_receipt_sha256 = (
        final_source.receipt_sha256 if final_source is not None else "0" * 64
    )
    fields: dict[str, object] = {
        "bindings": {
            "interface_id": portable.identity,
            "interface_sha256": portable.sha256,
            "operation_id": plan.operation_id,
            "machine_binding_id": str(semantic_payload["component_id"]),
            "machine_binding_sha256": semantic_bindings["machine_binding_sha256"],
            "machine_semantic_contract_id": f"semantic:{semantic_payload['component_id']}",
            "machine_semantic_contract_sha256": semantic.contract_sha256,
            "source_plan_sha256": plan.plan_sha256,
            "cutpoint_relation_sha256": relation.relation_sha256,
            "implementation_sha256": source["implementation_sha256"],
        },
        "dependencies": [
            {
                "id": "proof-declaration",
                "kind": "operator-invariant-declaration",
                "sha256": proof.declaration_sha256,
            }
        ],
        "receipts": [
            {
                "kind": "machine_semantics",
                "receipt_id": "machine-check",
                "receipt_sha256": machine.receipt_sha256,
                "operation_id": plan.operation_id,
                "semantic_contract_sha256": semantic.contract_sha256,
            },
            {
                "kind": "source_semantics",
                "receipt_id": "source-check",
                "receipt_sha256": source_receipt_sha256,
                "operation_id": plan.operation_id,
                "semantic_contract_sha256": semantic.contract_sha256,
            },
        ],
        "machine": {
            "unit_ids": sorted(
                str(item["unit_id"])
                for item in _rows(shape["semantic_units"], "machine units")
            ),
            "sccs": sorted(machine_sccs, key=lambda item: str(item["id"])),
        },
        "variables": sorted(variables, key=lambda item: str(item["id"])),
        "predicates": sorted(predicates, key=lambda item: str(item["id"])),
        "initialization": sorted(initialization, key=lambda item: str(item["id"])),
        "preservation": sorted(preservation, key=lambda item: str(item["id"])),
        "bridges": sorted(bridges, key=lambda item: str(item["id"])),
        "decreases": sorted(decreases, key=lambda item: str(item["id"])),
        "exits": sorted(exits, key=lambda item: str(item["id"])),
        "completions": sorted(completions, key=lambda item: str(item["id"])),
    }
    certificate = InductiveOperationCertificateV1.create(**fields)
    payloads = {"machine-check": machine.to_payload()}
    if final_source is not None:
        payloads["source-check"] = final_source.to_payload()
    check = check_inductive_operation_certificate(
        certificate, receipt_payloads=payloads
    )
    if check.status == "violated":
        raise InductiveCertificateError(
            "materialized certificate contradicts exact artifacts: "
            + "; ".join(item.code for item in check.issues)
        )
    if final_source is not None and check.status != "complete":
        raise InductiveCertificateError(
            "final induction certificate remains incomplete: "
            + "; ".join(item.code for item in check.issues)
        )
    return certificate


def write_inductive_certificate(
    *,
    out: Path | str,
    **inputs: object,
) -> InductiveOperationCertificateV1:
    certificate = materialize_inductive_certificate(**inputs)
    write_json(Path(out), certificate.to_payload())
    return certificate


def _check_acyclic_bridge_graph(
    scc_members: Mapping[str, set[str]],
    bridges_by_scc: Mapping[str, list[Mapping[str, object]]],
    cutpoint_owner: Mapping[str, str],
    direct_entry_sccs: set[str],
) -> None:
    graph: dict[str, set[str]] = {identity: set() for identity in scc_members}
    for source_scc, segments in bridges_by_scc.items():
        for segment in segments:
            target = _mapping(segment["target"], "bridge target")
            graph[source_scc].add(cutpoint_owner[str(target["id"])])

    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(identity: str) -> None:
        if identity in visited:
            return
        if identity in visiting:
            raise InductiveCertificateError(
                "cross-SCC bridge graph is cyclic and needs one combined invariant SCC"
            )
        visiting.add(identity)
        for target in sorted(graph[identity]):
            visit(target)
        visiting.remove(identity)
        visited.add(identity)

    for identity in sorted(graph):
        visit(identity)

    reachable = set(direct_entry_sccs)
    frontier = list(sorted(direct_entry_sccs))
    while frontier:
        source = frontier.pop()
        for target in sorted(graph[source]):
            if target not in reachable:
                reachable.add(target)
                frontier.append(target)
    if reachable != set(scc_members):
        raise InductiveCertificateError(
            "every exact SCC must be reachable from an operation-entry segment"
        )


def _derive_variables(
    interface: ProofKernelComponentInterface,
    plan: InductiveSourcePlanV1,
    relation: InductiveCutpointRelationV1,
) -> list[dict[str, object]]:
    operation = interface.operation_index()[plan.operation_id]
    types = interface.type_index()
    result: list[dict[str, object]] = []
    used: set[str] = set()
    for parameter in operation.parameters:
        if parameter.identity in used:
            raise InductiveCertificateError("logical variable identities overlap")
        used.add(parameter.identity)
        logical_type = types[parameter.type_id]
        domain = _domain(logical_type)
        if logical_type.kind == "bytes" and logical_type.nul_terminated:
            extent_variable_id = f"{parameter.identity}:extent"
            if extent_variable_id in used:
                raise InductiveCertificateError(
                    "generated NUL extent identity overlaps a logical variable"
                )
            domain = {
                "kind": "nul_terminated_bytes",
                "extent_variable_id": extent_variable_id,
                "access": logical_type.access,
            }
        result.append(
            {
                "id": parameter.identity,
                "type_id": parameter.type_id,
                "domain": domain,
                "origin": {
                    "kind": "operation_parameter",
                    "value_id": parameter.identity,
                },
            }
        )
        if logical_type.kind == "bytes" and logical_type.nul_terminated:
            used.add(extent_variable_id)
            result.append(
                {
                    "id": extent_variable_id,
                    "type_id": "builtin:u32",
                    "domain": {
                        "kind": "unsigned",
                        "width": 32,
                        "minimum": 1,
                        "maximum": 0xFFFFFFFF,
                    },
                    "origin": {
                        "kind": "byte_extent",
                        "view_id": parameter.identity,
                    },
                }
            )
    first_cutpoint = min(item.unit_id for item in relation.cutpoints)
    for field in plan.state:
        if field.identity in used:
            raise InductiveCertificateError("logical variable identities overlap")
        used.add(field.identity)
        result.append(
            {
                "id": field.identity,
                "type_id": field.type_id,
                "domain": _domain(types[field.type_id]),
                "origin": {
                    "kind": "cutpoint_value",
                    "cutpoint_id": first_cutpoint,
                },
            }
        )
    return result


def _domain(logical_type: ProofKernelLogicalType) -> dict[str, object]:
    if logical_type.kind in {"scalar", "enum"} and logical_type.c_type is not None:
        match = re.fullmatch(r"u?int(8|16|32)_t", logical_type.c_type)
        if match is not None:
            width = int(match.group(1))
            return {
                "kind": "unsigned",
                "width": width,
                "minimum": 0,
                "maximum": (1 << width) - 1,
            }
    if logical_type.kind == "bytes" and logical_type.extent_parameter_id is not None:
        return {
            "kind": "bounded_bytes",
            "extent_variable_id": logical_type.extent_parameter_id,
            "access": logical_type.access,
        }
    return {"kind": "unsupported", "feature": f"type-{logical_type.kind}"}


def _combine(op: str, values: list[Mapping[str, object]]) -> dict[str, object]:
    if not values:
        return {"op": "true"} if op == "and" else {"op": "false"}
    result = copy.deepcopy(dict(values[0]))
    for value in values[1:]:
        result = {"op": op, "args": [result, copy.deepcopy(dict(value))]}
    return result


def _substitute_state(
    value: object, updates: Mapping[str, object]
) -> dict[str, object]:
    row = _mapping(value, "ranking expression")
    if row.get("op") in {"loop_variable", "state_input"}:
        name = str(row.get("name"))
        if name in updates:
            replacement = _mapping(updates[name], "ranking state update")
            return copy.deepcopy(dict(replacement))
    result: dict[str, object] = {}
    for key, item in row.items():
        if isinstance(item, Mapping):
            result[str(key)] = _substitute_state(item, updates)
        elif isinstance(item, list):
            result[str(key)] = [
                _substitute_state(child, updates)
                if isinstance(child, Mapping)
                else copy.deepcopy(child)
                for child in item
            ]
        else:
            result[str(key)] = copy.deepcopy(item)
    return result


def _short_id(value: str) -> str:
    return canonical_sha256_v3(value)[:20]


def _load_source_receipt(
    value: Path | str | Mapping[str, object] | CheckedInductiveSourceReceiptV1 | None,
) -> CheckedInductiveSourceReceiptV1 | None:
    if value is None:
        return None
    if isinstance(value, CheckedInductiveSourceReceiptV1):
        return value
    return CheckedInductiveSourceReceiptV1.parse(
        _load(value, "inductive source receipt")
    )


def _load(value: Path | str | Mapping[str, object], context: str) -> dict[str, object]:
    if isinstance(value, Mapping):
        return json.loads(json.dumps(value))
    try:
        loaded = json.loads(Path(value).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise InductiveCertificateError(f"cannot read {context}: {exc}") from exc
    if not isinstance(loaded, Mapping):
        raise InductiveCertificateError(f"{context} must be an object")
    return dict(loaded)


__all__ = [
    "INDUCTIVE_PROOF_DECLARATION_V1",
    "InductiveCertificateError",
    "InductiveProofDeclarationV1",
    "materialize_inductive_certificate",
    "write_inductive_certificate",
]

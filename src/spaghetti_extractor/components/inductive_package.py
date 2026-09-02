"""Materialize checked induction artifacts from a small operator declaration.

The declaration chooses a useful logical decomposition.  It never contains
generated hashes, SCC identities, or segment identities.  Those facts are
derived from the exact semantic contract and bound into separate immutable
artifacts here.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from ..artifacts.artifact_set import canonical_sha256_v3
from ..util import write_json
from .inductive_receipts import build_inductive_machine_receipt
from .inductive_relation import InductiveCutpointRelationV1
from .inductive_source import InductiveSourcePlanV1
from .interface_ir import ProofKernelComponentInterface
from .semantic_contract import ProofKernelSemanticContract


INDUCTIVE_DECLARATION_V1 = "spaghetti-extractor-inductive-declaration-v1"
INDUCTIVE_COMPONENT_DECLARATION_V1 = (
    "spaghetti-extractor-inductive-component-declaration-v1"
)
INDUCTIVE_PACKAGE_V1 = "spaghetti-extractor-inductive-package-v1"

_ID = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9_.:-]*[A-Za-z0-9])?\Z")


class InductivePackageError(ValueError):
    """An induction declaration is malformed or contradicts exact semantics."""


def _object(value: object, fields: set[str], context: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise InductivePackageError(
            f"{context} must contain exactly {sorted(fields)!r}"
        )
    return value


def _mapping(value: object, context: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise InductivePackageError(f"{context} must be an object")
    return value


def _rows(value: object, context: str) -> list[Mapping[str, object]]:
    if not isinstance(value, list) or any(not isinstance(item, Mapping) for item in value):
        raise InductivePackageError(f"{context} must be an array of objects")
    return list(value)


def _identifier(value: object, context: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise InductivePackageError(f"{context} is not a canonical identifier")
    return value


def _identifiers(value: object, context: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise InductivePackageError(f"{context} must be a nonempty array")
    result = tuple(_identifier(item, context) for item in value)
    if list(result) != sorted(result) or len(result) != len(set(result)):
        raise InductivePackageError(f"{context} must be ordered and unique")
    return result


@dataclass(frozen=True)
class CompletionRouteV1:
    source_kind: str
    source_id: str
    target_exit_unit_id: str
    completion_id: str

    @classmethod
    def parse(cls, value: object, context: str) -> "CompletionRouteV1":
        row = _object(
            value,
            {"source", "target_exit_unit_id", "completion_id"},
            context,
        )
        source = _object(row["source"], {"kind", "id"}, f"{context} source")
        kind = _identifier(source["kind"], f"{context} source kind")
        if kind not in {"operation_entry", "cutpoint"}:
            raise InductivePackageError(f"{context} source kind is unsupported")
        return cls(
            kind,
            _identifier(source["id"], f"{context} source id"),
            _identifier(row["target_exit_unit_id"], f"{context} target exit"),
            _identifier(row["completion_id"], f"{context} completion"),
        )

    def key(self) -> tuple[str, str, str]:
        return self.source_kind, self.source_id, self.target_exit_unit_id


@dataclass(frozen=True)
class InductiveDeclarationV1:
    operation_id: str
    state: tuple[Mapping[str, object], ...]
    phase_ids: tuple[str, ...]
    completion_ids: tuple[str, ...]
    symbols: Mapping[str, object]
    cutpoints: tuple[Mapping[str, object], ...]
    completion_routes: tuple[CompletionRouteV1, ...]
    declaration_sha256: str

    @classmethod
    def parse(cls, value: object) -> "InductiveDeclarationV1":
        if isinstance(value, Mapping) and value.get("format") == INDUCTIVE_COMPONENT_DECLARATION_V1:
            combined = _object(
                value,
                {"format", "source", "proof"},
                "inductive component declaration",
            )
            source = _mapping(combined["source"], "inductive source declaration")
            return cls.parse({"format": INDUCTIVE_DECLARATION_V1, **source})
        row = _object(
            value,
            {
                "format",
                "operation_id",
                "state",
                "phase_ids",
                "completion_ids",
                "symbols",
                "cutpoints",
                "completion_routes",
            },
            "inductive declaration",
        )
        if row["format"] != INDUCTIVE_DECLARATION_V1:
            raise InductivePackageError("unsupported inductive declaration format")
        state = tuple(_rows(row["state"], "inductive declaration state"))
        state_ids = [
            _identifier(
                _object(item, {"id", "type_id"}, "inductive state field")["id"],
                "inductive state field id",
            )
            for item in state
        ]
        if state_ids != sorted(state_ids) or len(state_ids) != len(set(state_ids)):
            raise InductivePackageError("inductive state fields must be ordered and unique")
        symbols = _object(
            row["symbols"],
            {"wrapper", "initialize", "step", "finish"},
            "inductive source symbols",
        )
        cutpoints = tuple(_rows(row["cutpoints"], "inductive cutpoints"))
        cutpoint_ids = [
            _identifier(
                _object(
                    item,
                    {"unit_id", "phase_id", "values", "derived"},
                    "inductive cutpoint",
                )["unit_id"],
                "inductive cutpoint unit",
            )
            for item in cutpoints
        ]
        if not cutpoints or cutpoint_ids != sorted(cutpoint_ids) or len(cutpoint_ids) != len(set(cutpoint_ids)):
            raise InductivePackageError("inductive cutpoints must be nonempty, ordered, and unique")
        routes = tuple(
            CompletionRouteV1.parse(item, f"completion route {index}")
            for index, item in enumerate(
                _rows(row["completion_routes"], "completion routes")
            )
        )
        route_keys = [item.key() for item in routes]
        if not routes or route_keys != sorted(route_keys) or len(route_keys) != len(set(route_keys)):
            raise InductivePackageError("completion routes must be nonempty, ordered, and unique")
        canonical = json.loads(json.dumps(row))
        return cls(
            _identifier(row["operation_id"], "inductive operation"),
            tuple(json.loads(json.dumps(item)) for item in state),
            _identifiers(row["phase_ids"], "inductive phases"),
            _identifiers(row["completion_ids"], "inductive completions"),
            json.loads(json.dumps(symbols)),
            tuple(json.loads(json.dumps(item)) for item in cutpoints),
            routes,
            canonical_sha256_v3(canonical),
        )


def materialize_inductive_package(
    *,
    declaration: Path | str | Mapping[str, object],
    interface: Path | str | Mapping[str, object],
    semantic_contract: Path | str | Mapping[str, object],
) -> dict[str, object]:
    """Derive exact source-plan, machine-receipt, and relation artifacts."""

    declaration_payload = _load(declaration, "inductive declaration")
    authored = InductiveDeclarationV1.parse(declaration_payload)
    portable = ProofKernelComponentInterface.parse(
        _load(interface, "portable component interface")
    )
    semantic = ProofKernelSemanticContract.parse(
        _load(semantic_contract, "component semantic contract")
    )
    if semantic.status != "satisfied":
        raise InductivePackageError(
            "inductive artifacts require a satisfied exact semantic contract"
        )
    semantic_payload = semantic.to_payload()
    bindings = _object(
        semantic_payload["bindings"],
        set(semantic_payload["bindings"]),
        "semantic contract bindings",
    )
    if bindings.get("interface_sha256") != portable.sha256:
        raise InductivePackageError(
            "semantic contract and portable interface bindings differ"
        )
    operations = [
        item
        for item in _rows(semantic_payload["operations"], "semantic operations")
        if item.get("operation_id") == authored.operation_id
    ]
    if len(operations) != 1:
        raise InductivePackageError(
            "inductive declaration operation is absent or ambiguous"
        )
    operation = operations[0]
    plan = InductiveSourcePlanV1.create(
        interface=portable,
        operation_id=authored.operation_id,
        state=authored.state,
        phase_ids=authored.phase_ids,
        completion_ids=authored.completion_ids,
        symbols=authored.symbols,
    )
    plan.validate_for(
        portable, {authored.operation_id: plan.symbols.wrapper}
    )
    machine = build_inductive_machine_receipt(
        operation=operation,
        semantic_contract_sha256=semantic.contract_sha256,
        cutpoint_unit_ids=[str(item["unit_id"]) for item in authored.cutpoints],
    )
    inventory = machine.segment_inventory.to_value()
    assert isinstance(inventory, dict)
    routes = {item.key(): item for item in authored.completion_routes}
    used_routes: set[tuple[str, str, str]] = set()
    completion_segments: list[dict[str, object]] = []
    for segment in _rows(inventory["segments"], "exact inductive segments"):
        target = segment.get("target")
        source = segment.get("source")
        if not isinstance(target, Mapping) or target.get("kind") != "operation_exit":
            continue
        if not isinstance(source, Mapping):
            raise InductivePackageError("exact segment source is malformed")
        key = (
            str(source.get("kind")),
            str(source.get("id")),
            str(target.get("id")),
        )
        route = routes.get(key)
        if route is None:
            raise InductivePackageError(
                "no completion route covers exact segment "
                f"{segment.get('segment_id')!r} ({key!r})"
            )
        used_routes.add(key)
        completion_segments.append(
            {
                "segment_id": segment["segment_id"],
                "completion_id": route.completion_id,
            }
        )
    if used_routes != set(routes):
        raise InductivePackageError(
            "completion declaration contains routes with no exact segment: "
            f"{sorted(set(routes) - used_routes)!r}"
        )
    relation = InductiveCutpointRelationV1.create(
        interface=portable,
        source_plan=plan,
        machine_receipt=machine,
        cutpoints=authored.cutpoints,
        completion_segments=sorted(
            completion_segments, key=lambda item: str(item["segment_id"])
        ),
    )
    artifacts = {
        "source_plan": {
            "path": "source-plan.json",
            "sha256": plan.plan_sha256,
        },
        "machine_receipt": {
            "path": "machine-receipt.json",
            "sha256": machine.receipt_sha256,
        },
        "cutpoint_relation": {
            "path": "cutpoint-relation.json",
            "sha256": relation.relation_sha256,
        },
    }
    core: dict[str, object] = {
        "format": INDUCTIVE_PACKAGE_V1,
        "status": "checked",
        "component_id": semantic_payload["component_id"],
        "operation_id": authored.operation_id,
        "bindings": {
            "declaration_sha256": authored.declaration_sha256,
            "interface_sha256": portable.sha256,
            "semantic_contract_sha256": semantic.contract_sha256,
        },
        "artifacts": artifacts,
        "policy": {
            "original_binary_executed": False,
            "operator_behavior_examples_accepted": False,
            "generated_hashes_accepted_from_operator": False,
            "generated_segment_ids_accepted_from_operator": False,
            "exact_machine_inventory_replayed": True,
        },
    }
    return {
        "manifest": {**core, "package_sha256": canonical_sha256_v3(core)},
        "source_plan": plan.to_payload(),
        "machine_receipt": machine.to_payload(),
        "cutpoint_relation": relation.to_payload(),
    }


def write_inductive_package(
    *,
    declaration: Path | str | Mapping[str, object],
    interface: Path | str | Mapping[str, object],
    semantic_contract: Path | str | Mapping[str, object],
    out_dir: Path | str,
) -> dict[str, object]:
    package = materialize_inductive_package(
        declaration=declaration,
        interface=interface,
        semantic_contract=semantic_contract,
    )
    output = Path(out_dir)
    output.mkdir(parents=True, exist_ok=True)
    write_json(output / "source-plan.json", package["source_plan"])
    write_json(output / "machine-receipt.json", package["machine_receipt"])
    write_json(output / "cutpoint-relation.json", package["cutpoint_relation"])
    write_json(output / "induction-package.json", package["manifest"])
    return package


def _load(value: Path | str | Mapping[str, object], context: str) -> dict[str, object]:
    if isinstance(value, Mapping):
        return json.loads(json.dumps(value))
    try:
        loaded = json.loads(Path(value).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise InductivePackageError(f"cannot read {context}: {exc}") from exc
    if not isinstance(loaded, Mapping):
        raise InductivePackageError(f"{context} must be an object")
    return dict(loaded)


__all__ = [
    "INDUCTIVE_DECLARATION_V1",
    "INDUCTIVE_COMPONENT_DECLARATION_V1",
    "INDUCTIVE_PACKAGE_V1",
    "CompletionRouteV1",
    "InductiveDeclarationV1",
    "InductivePackageError",
    "materialize_inductive_package",
    "write_inductive_package",
]

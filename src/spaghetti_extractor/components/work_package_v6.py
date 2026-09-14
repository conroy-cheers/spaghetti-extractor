"""Direct semantic-module work packages for operator-authored components.

V6 is deliberately a projection, not an authority reducer.  It binds a V5
human-facing interface and operator component intent directly to a V2 linked
semantic module, a content-addressed semantic slice, and immutable faithful-C
source excerpts.  It does not consume component-contract V4, machine-binding
V5, implementation V4, or their facet receipts.
"""

from __future__ import annotations

import json
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3
from ..boundary._canonical import BoundaryModelError, canonical
from ..semantic_link.module_v2 import LinkedSemanticModuleV2
from ..semantic_providers.slices_v2 import (
    SemanticSliceV2,
    build_semantic_slice_v2,
)
from ..transfer.formats import EXECUTABLE_TRANSFER_PLAN_FORMAT
from ..transfer.plan import load_executable_transfer_plan
from ..util import sha256_file, sha256_text, write_json
from .binding_intent import ComponentMachineBindingIntentV1
from .formats import (
    COMPONENT_WORK_PACKAGE_V6_FORMAT,
)
from .interface_package_v5 import (
    CompiledComponentInterfaceV5,
    ComponentInterfaceIntentV1,
    compile_component_interface_v5,
)
from .source import component_operation_symbols, load_component_source_package


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_FIELDS = {
    "format", "status", "authority", "component_id",
    "proof_classification", "bindings", "operations", "semantic_slice",
    "faithful_c_slices", "requirements", "blockers", "suggested_tests",
    "generated_files", "policy", "work_package_sha256",
}
_POLICY = {
    "authorizes_implementation": False,
    "generated_baseline_mutable": False,
    "operator_machine_hashes_required": False,
    "tests_authorize": False,
}


class ComponentWorkPackageV6Error(BoundaryModelError):
    """A V6 work package is malformed, stale, or disconnected."""


def _fail(message: str) -> None:
    raise ComponentWorkPackageV6Error(message)


def _mapping(value: object, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        _fail(f"{context} must be an object")
    return value


def _rows(value: object, context: str) -> list[Mapping[str, Any]]:
    if not isinstance(value, list) or any(
        not isinstance(row, Mapping) for row in value
    ):
        _fail(f"{context} must be an array of objects")
    return list(value)


def _digest(value: object, context: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        _fail(f"{context} must be lowercase SHA-256")
    return value


@dataclass(frozen=True)
class ComponentWorkPackageV6:
    payload: Mapping[str, Any]
    public_header: str = ""
    operation_skeleton: str = ""

    @property
    def identity(self) -> str:
        return str(self.payload["work_package_sha256"])

    @classmethod
    def parse(cls, value: object) -> "ComponentWorkPackageV6":
        payload = dict(_mapping(value, "component work package V6"))
        if set(payload) != _FIELDS:
            _fail("component work-package V6 fields are incomplete")
        if payload.get("format") != COMPONENT_WORK_PACKAGE_V6_FORMAT:
            _fail("component work-package V6 format is unsupported")
        if payload.get("status") != "ready" or payload.get("authority") is not False:
            _fail("component work-package V6 must be ready and non-authorizing")
        declared = _digest(
            payload.get("work_package_sha256"), "component work-package identity"
        )
        core = {
            key: item for key, item in payload.items()
            if key != "work_package_sha256"
        }
        if declared != canonical_sha256_v3(core):
            _fail("component work-package V6 self hash is stale")
        if payload.get("proof_classification") not in {
            "machine_overlay", "encapsulated_owned",
        }:
            _fail("component work-package V6 proof classification is unsupported")
        if payload.get("policy") != _POLICY:
            _fail("component work-package V6 policy is stale")
        blockers = _rows(payload.get("blockers"), "work-package blockers")
        for blocker in blockers:
            frontier = blocker.get("review_frontier")
            if frontier is not None:
                _validate_review_frontier(frontier)
        bindings = _mapping(payload.get("bindings"), "work-package bindings")
        if set(bindings) != {
            "linked_semantic_module_sha256", "semantic_slice_sha256",
            "executable_transfer_plan_sha256", "interface_sha256",
            "schema_sha256", "binding_intent_sha256",
            "behavioral_c_source_map_sha256",
        } or any(_digest(item, f"work-package binding {key}") != item
                 for key, item in bindings.items()):
            _fail("component work-package V6 bindings are malformed")
        semantic_slice = SemanticSliceV2.parse(payload.get("semantic_slice"))
        if semantic_slice.identity != bindings["semantic_slice_sha256"]:
            _fail("component work-package V6 semantic-slice binding is stale")
        operations = _rows(payload.get("operations"), "work-package operations")
        operation_ids = [str(row.get("operation_id")) for row in operations]
        if not operations or operation_ids != sorted(set(operation_ids)):
            _fail("component work-package V6 operations are empty or duplicated")
        slice_definitions = {
            str(row["definition_id"])
            for row in semantic_slice.payload["definitions"]
        }
        owned_definitions: set[str] = set()
        for row in operations:
            required = {
                "operation_id", "symbol", "signature_id", "semantic_sha256",
                "definition_ids", "unit_ids", "context_transfer_ids",
                "entry_rvas", "entry_unit_ids", "exit_unit_ids",
                "projection_sha256", "projection_receipt_sha256",
                "lifecycle_sha256", "lifecycle_receipt_sha256", "effect_ids",
                "service_ids", "callback_ids", "outcome_protocol_ids",
                "object_authority_selectors", "pointer_views",
                "machine_projection",
            }
            if set(row) != required:
                _fail("component work-package V6 operation fields are incomplete")
            definition_ids = row.get("definition_ids")
            if (
                not isinstance(definition_ids, list) or not definition_ids
                or definition_ids != sorted(set(definition_ids))
            ):
                _fail("component work-package V6 operation definitions are malformed")
            owned_definitions.update(str(item) for item in definition_ids)
        if owned_definitions != slice_definitions:
            _fail("component work-package V6 operations and slice disagree")
        slices = _rows(payload.get("faithful_c_slices"), "faithful-C slices")
        slice_units = [str(row.get("unit_id")) for row in slices]
        if not slices or slice_units != sorted(set(slice_units)):
            _fail("component work-package V6 faithful-C slices are malformed")
        for row in slices:
            if set(row) != {
                "unit_id", "source_path", "source_sha256", "rva_start",
                "rva_end", "line_start", "line_end",
            }:
                _fail("component work-package V6 faithful-C slice is incomplete")
            _digest(row.get("source_sha256"), "faithful-C source")
            if (
                not isinstance(row.get("rva_start"), int)
                or not isinstance(row.get("rva_end"), int)
                or row["rva_end"] <= row["rva_start"]
                or not isinstance(row.get("line_start"), int)
                or not isinstance(row.get("line_end"), int)
                or row["line_start"] < 1
                or row["line_end"] < row["line_start"]
            ):
                _fail("component work-package V6 faithful-C span is invalid")
        generated = _rows(payload.get("generated_files"), "generated files")
        if [row.get("path") for row in generated] != [
            "include/component.h", "src/component.c",
        ] or any(set(row) != {"path", "sha256"} for row in generated):
            _fail("component work-package V6 generated-file inventory is malformed")
        for row in generated:
            _digest(row.get("sha256"), "generated file")
        return cls(payload)


def build_component_work_package_v6(
    *,
    component_id: str,
    interface_package: Path,
    binding_intent: Path,
    linked_semantic_module: Path,
    behavioral_c_package: Path,
    out: Path,
    source_package: Path | None = None,
    proof_classification: str = "machine_overlay",
) -> ComponentWorkPackageV6:
    """Derive and publish one V6 package without legacy reducer artifacts."""

    output = Path(out)
    interface_root = Path(interface_package)
    intent = ComponentInterfaceIntentV1.parse(json.loads(
        (interface_root / "component-interface-intent-v1.json").read_text(
            encoding="utf-8"
        )
    ))
    bundle = compile_component_interface_v5(intent)
    binding = ComponentMachineBindingIntentV1.parse(json.loads(
        Path(binding_intent).read_text(encoding="utf-8")
    ))
    if (
        intent.component_id != component_id
        or binding.component_id != component_id
    ):
        _fail("component work-package V6 component identity is stale")
    interface_ids = [item.identity for item in bundle.interface.operations]
    binding_ids = [item.semantics.operation_id for item in binding.operations]
    if interface_ids != binding_ids:
        _fail("component work-package V6 operation mapping is not total")

    linked_path = Path(linked_semantic_module)
    linked = LinkedSemanticModuleV2.load(linked_path, require_complete=False)
    transfer_path = linked_path.parent / "executable-transfer-plan.json"
    transfer_payload, _ = load_executable_transfer_plan(
        transfer_path, require_complete=False
    )
    transfer_sha256 = sha256_file(transfer_path)
    if (
        linked.payload["bindings"]["executable_transfer_plan_sha256"]
        != transfer_payload["plan_sha256"]
    ):
        _fail("component work-package V6 transfer-plan identity is stale")

    inventory = {
        str(row["unit_id"]): row for row in transfer_payload["unit_inventory"]
    }
    behavioral_root = Path(behavioral_c_package)
    source_map_path = behavioral_root / "behavioral-c-source-map.json"
    source_map_payload = json.loads(source_map_path.read_text(encoding="utf-8"))
    source_map = {
        str(row["unit_id"]): row for row in source_map_payload["units"]
    }
    if source_map_payload.get("executable_transfer_plan_sha256") != transfer_sha256:
        _fail("component work-package V6 faithful-C source map is stale")

    if source_package is None:
        symbols = _default_operation_symbols(bundle)
    else:
        symbols = component_operation_symbols(
            load_component_source_package(source_package)
        )
    if sorted(symbols) != interface_ids:
        _fail("component work-package V6 operation-symbol map is not total")

    interface_operations = {
        item.identity: item for item in bundle.interface.operations
    }
    semantic_slice_payload, operation_definition_ids = (
        build_component_semantic_slice_v2(linked=linked, binding=binding)
    )
    semantic_slice = SemanticSliceV2.parse(semantic_slice_payload)
    contextual_units: set[str] = set()
    operations = []
    for operation in binding.operations:
        semantics = operation.semantics
        owned = operation_definition_ids[semantics.operation_id]
        contextual_units.update(semantics.transfer_ids)
        projection = _mapping(
            semantics.machine_projection.get("operation"),
            f"component operation {semantics.operation_id} projection",
        )
        interface_operation = interface_operations[semantics.operation_id]
        operations.append({
            "operation_id": semantics.operation_id,
            "symbol": symbols[semantics.operation_id],
            "signature_id": interface_operation.signature_id,
            "semantic_sha256": semantics.semantic_sha256,
            "definition_ids": sorted(owned),
            "unit_ids": list(semantics.unit_ids),
            "context_transfer_ids": list(semantics.transfer_ids),
            "entry_rvas": list(semantics.entry_rvas),
            "entry_unit_ids": sorted(set(projection.get("entry_unit_ids", []))),
            "exit_unit_ids": sorted(set(projection.get("exit_unit_ids", []))),
            "projection_sha256": interface_operation.projection_sha256,
            "projection_receipt_sha256": (
                interface_operation.projection_receipt_sha256
            ),
            "lifecycle_sha256": interface_operation.lifecycle_sha256,
            "lifecycle_receipt_sha256": (
                interface_operation.lifecycle_receipt_sha256
            ),
            "effect_ids": list(semantics.effect_ids),
            "service_ids": list(semantics.service_ids),
            "callback_ids": list(semantics.callback_ids),
            "outcome_protocol_ids": list(semantics.outcome_protocol_ids),
            "object_authority_selectors": canonical(list(
                operation.authority["object_authority_selectors"]
            )),
            "pointer_views": canonical(list(operation.authority["pointer_views"])),
            "machine_projection": canonical(dict(semantics.machine_projection)),
        })

    obligation_ids = [
        str(row["obligation_id"])
        for row in semantic_slice.payload["obligations"]
    ]

    baseline = []
    copied: dict[str, Path] = {}
    for unit_id in sorted(contextual_units):
        inventory_row = inventory.get(unit_id)
        map_row = source_map.get(unit_id)
        if inventory_row is None or map_row is None:
            _fail(f"faithful-C context unit {unit_id!r} is not mapped")
        relative = str(map_row["file"])
        source = behavioral_root / relative
        if not source.is_file():
            _fail(f"faithful-C context source {relative!r} is missing")
        copied.setdefault(relative, source)
        baseline.append({
            "unit_id": unit_id,
            "source_path": f"baseline/{relative}",
            "source_sha256": sha256_file(source),
            "rva_start": int(inventory_row["rva_start"]),
            "rva_end": int(inventory_row["rva_end"]),
            "line_start": int(map_row["line_start"]),
            "line_end": int(map_row["line_end"]),
        })

    services = sorted({item for row in operations for item in row["service_ids"]})
    callbacks = sorted({item for row in operations for item in row["callback_ids"]})
    outcomes = sorted({
        item for row in operations for item in row["outcome_protocol_ids"]
    })
    selectors = sorted(
        (canonical(dict(item)) for row in operations
         for item in row["object_authority_selectors"]),
        key=canonical_sha256_v3,
    )
    review_frontier = _machine_review_frontier(
        transfer_payload=transfer_payload,
        operations=operations,
        admitted_domains=linked.payload["admitted_domains"],
    )
    blockers = _rank_blockers(
        binding.blockers, review_frontier=review_frontier,
    )
    header = _render_public_header(bundle, symbols)
    skeleton = _render_operation_skeleton(
        bundle, symbols, semantic_slice.identity
    )
    core = {
        "format": COMPONENT_WORK_PACKAGE_V6_FORMAT,
        "status": "ready",
        "authority": False,
        "component_id": component_id,
        "proof_classification": proof_classification,
        "bindings": {
            "linked_semantic_module_sha256": linked.identity,
            "semantic_slice_sha256": semantic_slice.identity,
            "executable_transfer_plan_sha256": transfer_sha256,
            "interface_sha256": bundle.interface.interface_sha256,
            "schema_sha256": bundle.interface.schema_sha256,
            "binding_intent_sha256": binding.intent_sha256,
            "behavioral_c_source_map_sha256": sha256_file(source_map_path),
        },
        "operations": operations,
        "semantic_slice": semantic_slice_payload,
        "faithful_c_slices": baseline,
        "requirements": {
            "service_ids": services,
            "object_authority_selectors": selectors,
            "lifecycle_ids": [
                f"lifecycle-{row['operation_id']}" for row in operations
            ],
            "callback_ids": callbacks,
            "outcome_protocol_ids": outcomes,
            "obligation_ids": obligation_ids,
            "dependency_contract_sha256s": list(
                semantic_slice.payload["dependency_contract_sha256s"]
            ),
        },
        "blockers": blockers,
        "suggested_tests": [{
            "code": "component-contextual-refinement-case",
            "operation_id": row["operation_id"],
            "rank": index + 1,
            "veto_only": True,
        } for index, row in enumerate(operations)],
        "generated_files": [
            {"path": "include/component.h", "sha256": sha256_text(header)},
            {"path": "src/component.c", "sha256": sha256_text(skeleton)},
        ],
        "policy": _POLICY,
    }
    payload = {**core, "work_package_sha256": canonical_sha256_v3(core)}
    package = ComponentWorkPackageV6.parse(payload)
    package = ComponentWorkPackageV6(package.payload, header, skeleton)

    (output / "include").mkdir(parents=True, exist_ok=True)
    (output / "src").mkdir(parents=True, exist_ok=True)
    (output / "baseline").mkdir(parents=True, exist_ok=True)
    (output / "include/component.h").write_text(header, encoding="utf-8")
    (output / "src/component.c").write_text(skeleton, encoding="utf-8")
    for relative, source in copied.items():
        destination = output / "baseline" / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
    write_json(output / "semantic-slice-v2.json", semantic_slice_payload)
    write_json(output / "component-work-package-v6.json", package.payload)
    return package


def build_component_semantic_slice_v2(
    *, linked: LinkedSemanticModuleV2,
    binding: ComponentMachineBindingIntentV1,
) -> tuple[dict[str, object], dict[str, list[str]]]:
    """Project the reusable semantic slice without a module-wide binding."""

    definitions_by_symbol = {
        str(row["symbol_id"]): row for row in linked.payload["definitions"]
    }
    active_definition_ids = {
        str(row["definition_id"])
        for row in linked.payload["definition_requirements"]
        if row.get("definition_id") is not None
    }
    definition_ids: set[str] = set()
    subjects: set[str] = set()
    by_operation: dict[str, list[str]] = {}
    for operation in binding.operations:
        semantics = operation.semantics
        owned = []
        for unit_id in semantics.unit_ids:
            definition = definitions_by_symbol.get(f"original:function:{unit_id}")
            if definition is None:
                _fail(
                    f"component operation {semantics.operation_id!r} names no "
                    f"semantic definition for unit {unit_id!r}"
                )
            definition_id = str(definition["definition_id"])
            if definition_id not in active_definition_ids:
                _fail(
                    f"component operation {semantics.operation_id!r} names an "
                    f"inactive semantic definition {definition_id!r}"
                )
            owned.append(definition_id)
            definition_ids.add(definition_id)
        by_operation[semantics.operation_id] = sorted(owned)
        subjects.update(semantics.transfer_ids)
        subjects.update(semantics.unit_ids)
        subjects.update(owned)
        subjects.update(f"original:function:{item}" for item in semantics.transfer_ids)
    obligation_ids = sorted(
        str(row["obligation_id"])
        for row in linked.payload["residual_obligations"]
        if _contains_exact_identity(row, subjects)
    )
    payload = build_semantic_slice_v2(
        linked_semantic_module=linked,
        definition_ids=sorted(definition_ids),
        obligation_ids=obligation_ids,
    )
    return payload, by_operation


def write_component_semantic_slice_v2(
    *, linked_semantic_module: Path, binding_intent: Path, out: Path,
) -> dict[str, object]:
    """Write the independently reusable component semantic-slice artifact."""

    linked = LinkedSemanticModuleV2.load(
        Path(linked_semantic_module), require_complete=False
    )
    binding = ComponentMachineBindingIntentV1.parse(json.loads(
        Path(binding_intent).read_text(encoding="utf-8")
    ))
    payload, _ = build_component_semantic_slice_v2(
        linked=linked, binding=binding
    )
    SemanticSliceV2.parse(payload)
    write_json(Path(out), payload)
    return payload


def _contains_exact_identity(value: object, subjects: set[str]) -> bool:
    if isinstance(value, str):
        return value in subjects
    if isinstance(value, Mapping):
        return any(_contains_exact_identity(item, subjects) for item in value.values())
    if isinstance(value, (list, tuple)):
        return any(_contains_exact_identity(item, subjects) for item in value)
    return False


def _rank_blockers(
    blockers: Sequence[Mapping[str, object]],
    *,
    review_frontier: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    ordered = sorted(
        (canonical(dict(item)) for item in blockers), key=canonical_sha256_v3
    )
    result = []
    for index, row in enumerate(ordered):
        ranked = {
            "rank": index + 1,
            "source": "component_binding_intent",
            **row,
        }
        if (
            review_frontier is not None
            and row.get("code")
            == "machine_effect_service_callback_outcome_projection_unreviewed"
        ):
            ranked["review_frontier"] = canonical(dict(review_frontier))
        result.append(ranked)
    return result


def _machine_review_frontier(
    *,
    transfer_payload: Mapping[str, Any],
    operations: Sequence[Mapping[str, object]],
    admitted_domains: Sequence[Mapping[str, Any]] = (),
) -> dict[str, object]:
    """Project exact machine observations needed to review an honest blocker.

    This remains inside the blocker and is not a provider input. Its only
    suggestions are exact normalized-name matches between a declared service
    and a named import, plus checked interface methods whose vtable offset
    exactly matches a syntactic ``load(vtable + constant)`` target.  Neither
    projection adopts a binding: register provenance and receiver identity
    remain for the operator to review.
    """

    transfers = {
        str(row["identity"]): row
        for row in _rows(
            transfer_payload.get("transfers"), "review-frontier transfers"
        )
    }
    interface_candidates = _interface_method_candidates_by_offset(
        admitted_domains
    )
    observation_rows = []
    for operation in operations:
        operation_id = str(operation["operation_id"])
        declared_services = sorted(str(item) for item in operation["service_ids"])
        transfer_ids = [str(item) for item in operation["context_transfer_ids"]]
        call_events: list[dict[str, object]] = []
        write_effects: list[dict[str, object]] = []
        outcomes: list[dict[str, object]] = []
        for transfer_id in transfer_ids:
            transfer = transfers.get(transfer_id)
            if transfer is None:
                _fail(
                    f"review frontier names unknown transfer {transfer_id!r}"
                )
            source = canonical(dict(_mapping(
                transfer.get("source"), f"review transfer {transfer_id} source",
            )))
            expressions = _rows(
                transfer.get("expressions"),
                f"review transfer {transfer_id} expressions",
            )
            for call in _rows(
                transfer.get("calls"), f"review transfer {transfer_id} calls"
            ):
                call_payload = canonical(dict(call))
                expression_nodes = _expression_closure(
                    expressions,
                    _call_expression_roots(call_payload),
                    context=f"call in {transfer_id}",
                )
                structural_candidates = _structural_interface_candidates(
                    call=call_payload,
                    expression_nodes=expression_nodes,
                    candidates_by_offset=interface_candidates,
                    declared_service_ids=declared_services,
                )
                event_core = {
                    "transfer_id": transfer_id,
                    "source": source,
                    "event_index": int(call_payload["event_index"]),
                    "call": call_payload,
                    "expression_nodes": expression_nodes,
                    "structural_interface_candidates": structural_candidates,
                }
                event_sha256 = canonical_sha256_v3(event_core)
                call_events.append({
                    **event_core,
                    "event_id": f"machine-call:{event_sha256}",
                    "event_sha256": event_sha256,
                })
            for effect in _rows(
                transfer.get("effects"),
                f"review transfer {transfer_id} effects",
            ):
                if effect.get("op") != "memory_write":
                    continue
                effect_payload = canonical(dict(effect))
                operands = effect_payload.get("operands")
                roots = (
                    [int(item) for item in operands]
                    if isinstance(operands, list)
                    else []
                )
                effect_core = {
                    "transfer_id": transfer_id,
                    "source": source,
                    "effect": effect_payload,
                    "expression_nodes": _expression_closure(
                        expressions, roots, context=f"write in {transfer_id}",
                    ),
                }
                write_effects.append({
                    **effect_core,
                    "effect_sha256": canonical_sha256_v3(effect_core),
                })
            terminator = canonical(dict(_mapping(
                transfer.get("terminator"),
                f"review transfer {transfer_id} terminator",
            )))
            outcome_core = {
                "transfer_id": transfer_id,
                "source": source,
                "terminator": terminator,
                "expression_nodes": _expression_closure(
                    expressions,
                    _terminator_expression_roots(terminator),
                    context=f"outcome in {transfer_id}",
                ),
            }
            outcomes.append({
                **outcome_core,
                "outcome_sha256": canonical_sha256_v3(outcome_core),
            })

        call_events.sort(key=lambda row: (
            int(_mapping(row["call"], "review call")["instruction_rva"]),
            int(row["event_index"]),
            str(row["event_id"]),
        ))
        write_effects.sort(key=lambda row: (
            int(_mapping(row["source"], "review write source")["rva_start"]),
            int(_mapping(row["effect"], "review write effect")["id"]),
        ))
        outcomes.sort(key=lambda row: (
            int(_mapping(row["source"], "review outcome source")["rva_start"]),
            str(row["transfer_id"]),
        ))
        projection = _mapping(
            operation.get("machine_projection"),
            f"review operation {operation_id} machine projection",
        )
        bindings = _rows(
            projection.get("service_bindings", []),
            f"review operation {operation_id} service bindings",
        )
        mapped_services = sorted({
            str(row["service_id"])
            for row in bindings
            if isinstance(row.get("service_id"), str)
        })
        lexical_candidates = _lexical_service_candidates(
            declared_service_ids=declared_services,
            call_events=call_events,
        )
        unmapped_services = sorted(
            set(declared_services) - set(mapped_services)
        )
        observation_rows.append({
            "operation_id": operation_id,
            "declared_service_ids": declared_services,
            "mapped_service_ids": mapped_services,
            "unmapped_service_ids": unmapped_services,
            "exact_call_events": call_events,
            "memory_write_effects": write_effects,
            "control_outcomes": outcomes,
            "lexical_service_candidates": lexical_candidates,
            "counts": {
                "transfers": len(transfer_ids),
                "call_events": len(call_events),
                "named_external_calls": sum(
                    _mapping(row["call"], "review call").get("kind")
                    == "external_call"
                    for row in call_events
                ),
                "indirect_calls": sum(
                    _mapping(row["call"], "review call").get("kind")
                    == "indirect_call"
                    for row in call_events
                ),
                "internal_calls": sum(
                    _mapping(row["call"], "review call").get("kind")
                    == "internal_call"
                    for row in call_events
                ),
                "memory_writes": len(write_effects),
                "control_outcomes": len(outcomes),
                "declared_services": len(declared_services),
                "mapped_services": len(mapped_services),
                "unmapped_services": len(unmapped_services),
                "lexical_candidates": len(lexical_candidates),
                "structural_interface_candidates": sum(
                    len(row["structural_interface_candidates"])
                    for row in call_events
                ),
                "structurally_classified_indirect_calls": sum(
                    bool(row["structural_interface_candidates"])
                    for row in call_events
                ),
            },
        })
    observation_rows.sort(key=lambda row: str(row["operation_id"]))
    core = {
        "authority": False,
        "source_format": EXECUTABLE_TRANSFER_PLAN_FORMAT,
        "source_plan_sha256": str(transfer_payload["plan_sha256"]),
        "operations": observation_rows,
        "policy": {
            "adopts_service_bindings": False,
            "authorizes_effects": False,
            "authorizes_outcomes": False,
            "lexical_candidates_are_presentation_only": True,
            "structural_candidates_are_presentation_only": True,
            "tests_authorize": False,
        },
    }
    return {**core, "frontier_sha256": canonical_sha256_v3(core)}


def _call_expression_roots(call: Mapping[str, object]) -> list[int]:
    roots: list[int] = []
    target = call.get("target_node")
    if isinstance(target, int) and not isinstance(target, bool):
        roots.append(target)
    for field in ("register_nodes", "flag_nodes", "argument_nodes"):
        values = call.get(field)
        if isinstance(values, list):
            roots.extend(
                int(item) for item in values
                if isinstance(item, int) and not isinstance(item, bool)
            )
    stack_inputs = call.get("stack_inputs")
    if isinstance(stack_inputs, list):
        for row in stack_inputs:
            if (
                isinstance(row, list) and len(row) == 3
                and isinstance(row[2], int) and not isinstance(row[2], bool)
            ):
                roots.append(int(row[2]))
    return sorted(set(roots))


def _terminator_expression_roots(
    terminator: Mapping[str, object],
) -> list[int]:
    operands = terminator.get("operands")
    if not isinstance(operands, list):
        return []
    op = terminator.get("op")
    if op == "outcome_branch":
        values = operands[:1]
    elif op in {"outcome_return", "outcome_indirect", "outcome_nonlocal"}:
        values = operands
    else:
        values = []
    return [
        int(item) for item in values
        if isinstance(item, int) and not isinstance(item, bool)
    ]


def _expression_closure(
    expressions: Sequence[Mapping[str, Any]], roots: Sequence[int], *, context: str,
) -> list[Mapping[str, Any]]:
    by_id = {int(row["id"]): row for row in expressions}
    pending = list(roots)
    selected: set[int] = set()
    while pending:
        expression_id = pending.pop()
        if expression_id in selected:
            continue
        row = by_id.get(expression_id)
        if row is None:
            _fail(f"{context} references unknown expression {expression_id}")
        selected.add(expression_id)
        operands = row.get("operands")
        if not isinstance(operands, list) or any(
            not isinstance(item, int) or isinstance(item, bool)
            for item in operands
        ):
            _fail(f"{context} expression {expression_id} is malformed")
        pending.extend(int(item) for item in operands)
    return [canonical(dict(by_id[item])) for item in sorted(selected)]


def _lexical_service_candidates(
    *, declared_service_ids: Sequence[str],
    call_events: Sequence[Mapping[str, object]],
) -> list[dict[str, object]]:
    candidates = []
    by_name = {
        _normalized_presentation_name(service_id): service_id
        for service_id in declared_service_ids
    }
    for event in call_events:
        call = _mapping(event.get("call"), "review call")
        symbol = call.get("symbol")
        if call.get("kind") != "external_call" or not isinstance(symbol, str):
            continue
        service_id = by_name.get(
            _normalized_presentation_name(symbol, win32_symbol=True)
        )
        if service_id is None:
            continue
        candidates.append({
            "service_id": service_id,
            "rank": 1,
            "confidence": "exact_normalized_import_name_only",
            "event_id": str(event["event_id"]),
            "identity": {
                "dll": call.get("dll"),
                "symbol": symbol,
                "ordinal": call.get("ordinal"),
            },
            "authority": False,
        })
    return sorted(candidates, key=lambda row: (
        str(row["service_id"]), str(row["event_id"]),
    ))


def _interface_method_candidates_by_offset(
    admitted_domains: Sequence[Mapping[str, Any]],
) -> dict[int, list[dict[str, object]]]:
    """Compact the already-checked callable catalog for operator review."""

    by_offset: dict[int, list[dict[str, object]]] = {}
    seen: set[str] = set()
    for raw_domain in admitted_domains:
        domain = _mapping(raw_domain, "review callable domain")
        if domain.get("kind") != "checked_indirect_callable_targets_v3":
            continue
        domain_sha256 = _digest(
            domain.get("domain_sha256"), "review callable domain identity"
        )
        for raw_target in _rows(
            domain.get("external_interface_targets"),
            "review interface-method targets",
        ):
            target = _mapping(raw_target, "review interface-method target")
            method = _mapping(target.get("method"), "review interface method")
            protocol = _mapping(
                method.get("external_protocol"),
                "review interface-method protocol",
            )
            receiver = _mapping(
                method.get("receiver_resource"),
                "review interface-method receiver",
            )
            method_sha256 = _digest(
                target.get("method_contract_sha256"),
                "review interface-method contract",
            )
            profile_sha256 = _digest(
                target.get("profile_sha256"),
                "review interface-method profile",
            )
            offset = protocol.get("offset")
            slot = protocol.get("slot")
            method_name = protocol.get("method")
            argument_words = method.get("argument_words")
            if (
                protocol.get("kind") != "pe32-interface-method"
                or not isinstance(offset, int) or isinstance(offset, bool)
                or offset < 0 or offset % 4 != 0
                or slot != offset // 4
                or not isinstance(method_name, str) or not method_name
                or not isinstance(argument_words, int)
                or isinstance(argument_words, bool) or argument_words < 1
                or not isinstance(target.get("profile_id"), str)
                or not isinstance(target.get("interface_id"), str)
                or receiver.get("dispatch_slot") != slot
                or method_sha256 in seen
            ):
                _fail("review interface-method catalog is malformed")
            seen.add(method_sha256)
            by_offset.setdefault(offset, []).append({
                "authority": False,
                "confidence": "exact_syntactic_vtable_slot_offset_only",
                "admitted_domain_sha256": domain_sha256,
                "method_contract_sha256": method_sha256,
                "profile_id": str(target["profile_id"]),
                "profile_sha256": profile_sha256,
                "interface_id": str(target["interface_id"]),
                "method": method_name,
                "slot": slot,
                "offset": offset,
                "argument_words": argument_words,
                "receiver_resource": canonical(dict(receiver)),
            })
    for rows in by_offset.values():
        rows.sort(key=lambda row: (
            str(row["profile_sha256"]), str(row["interface_id"]),
            int(row["slot"]), str(row["method_contract_sha256"]),
        ))
    return by_offset


def _structural_interface_candidates(
    *,
    call: Mapping[str, object],
    expression_nodes: Sequence[Mapping[str, Any]],
    candidates_by_offset: Mapping[int, Sequence[Mapping[str, object]]],
    declared_service_ids: Sequence[str],
) -> list[dict[str, object]]:
    """Match only the local vtable-slot syntax, never receiver provenance."""

    if call.get("kind") != "indirect_call":
        return []
    target_node = call.get("target_node")
    if not isinstance(target_node, int) or isinstance(target_node, bool):
        return []
    by_id = {int(row["id"]): row for row in expression_nodes}
    target = by_id.get(target_node)
    if target is None or target.get("op") != "load":
        return []
    operands = target.get("operands")
    if not isinstance(operands, list) or len(operands) != 1:
        return []
    address = by_id.get(operands[0])
    if address is None or address.get("op") != "add32":
        return []
    address_operands = address.get("operands")
    if not isinstance(address_operands, list) or len(address_operands) != 2:
        return []
    children = [by_id.get(item) for item in address_operands]
    constants = [
        row for row in children
        if row is not None and row.get("op") == "const"
    ]
    registers = [
        row for row in children
        if row is not None and row.get("op") == "reg"
    ]
    if len(constants) != 1 or len(registers) != 1:
        return []
    parameters = _mapping(
        constants[0].get("parameters"), "review vtable-slot constant"
    )
    offset = parameters.get("immediate")
    if (
        not isinstance(offset, int) or isinstance(offset, bool)
        or offset < 0 or offset % 4 != 0
    ):
        return []
    service_by_name: dict[str, list[str]] = {}
    for service_id in declared_service_ids:
        service_by_name.setdefault(
            _normalized_presentation_name(service_id), []
        ).append(service_id)
    result = []
    for raw in candidates_by_offset.get(offset, ()):
        row = dict(raw)
        row["matching_declared_service_ids"] = sorted(service_by_name.get(
            _normalized_presentation_name(str(row["method"])), []
        ))
        result.append(row)
    return result


def _normalized_presentation_name(
    value: str, *, win32_symbol: bool = False,
) -> str:
    result = re.sub(r"[^a-z0-9]", "", value.lower())
    if win32_symbol and value.endswith(("A", "W")) and result:
        result = result[:-1]
    return result


def _validate_review_frontier(value: object) -> None:
    frontier = _mapping(value, "work-package review frontier")
    expected = {
        "authority", "source_format", "source_plan_sha256", "operations",
        "policy", "frontier_sha256",
    }
    if set(frontier) != expected or frontier.get("authority") is not False:
        _fail("work-package review frontier fields are malformed")
    if frontier.get("source_format") != EXECUTABLE_TRANSFER_PLAN_FORMAT:
        _fail("work-package review frontier source format is unsupported")
    _digest(frontier.get("source_plan_sha256"), "review-frontier source plan")
    declared = _digest(
        frontier.get("frontier_sha256"), "review-frontier identity"
    )
    core = {
        key: item for key, item in frontier.items()
        if key != "frontier_sha256"
    }
    if declared != canonical_sha256_v3(core):
        _fail("work-package review frontier self hash is stale")
    if frontier.get("policy") != {
        "adopts_service_bindings": False,
        "authorizes_effects": False,
        "authorizes_outcomes": False,
        "lexical_candidates_are_presentation_only": True,
        "structural_candidates_are_presentation_only": True,
        "tests_authorize": False,
    }:
        _fail("work-package review frontier policy is stale")
    operations = _rows(frontier.get("operations"), "review-frontier operations")
    operation_ids = [str(row.get("operation_id")) for row in operations]
    if operation_ids != sorted(set(operation_ids)):
        _fail("work-package review frontier operations are noncanonical")
    for operation in operations:
        _validate_review_operation(operation)


def _validate_review_operation(value: Mapping[str, Any]) -> None:
    expected = {
        "operation_id", "declared_service_ids", "mapped_service_ids",
        "unmapped_service_ids", "exact_call_events", "memory_write_effects",
        "control_outcomes", "lexical_service_candidates", "counts",
    }
    if set(value) != expected or not isinstance(value.get("operation_id"), str):
        _fail("review-frontier operation fields are malformed")
    declared = _canonical_text_ids(
        value.get("declared_service_ids"), "declared services"
    )
    mapped = _canonical_text_ids(
        value.get("mapped_service_ids"), "mapped services"
    )
    unmapped = _canonical_text_ids(
        value.get("unmapped_service_ids"), "unmapped services"
    )
    if not set(mapped) <= set(declared) or unmapped != sorted(
        set(declared) - set(mapped)
    ):
        _fail("review-frontier service coverage is contradictory")

    events = _rows(value.get("exact_call_events"), "review call events")
    event_ids = []
    for event in events:
        if set(event) != {
            "transfer_id", "source", "event_index", "call",
            "expression_nodes", "structural_interface_candidates",
            "event_id", "event_sha256",
        }:
            _fail("review-frontier call event fields are malformed")
        _review_source(event.get("source"), "review call source")
        _review_expressions(event.get("expression_nodes"), "review call expressions")
        if (
            not isinstance(event.get("transfer_id"), str)
            or not isinstance(event.get("event_index"), int)
            or isinstance(event.get("event_index"), bool)
            or event["event_index"] < 0
        ):
            _fail("review-frontier call identity is malformed")
        call = _mapping(event.get("call"), "review call")
        if (
            call.get("event_index") != event["event_index"]
            or call.get("kind")
            not in {"external_call", "internal_call", "indirect_call"}
            or not isinstance(call.get("instruction_rva"), int)
            or isinstance(call.get("instruction_rva"), bool)
        ):
            _fail("review-frontier call payload is malformed")
        event_core = {
            key: item for key, item in event.items()
            if key not in {"event_id", "event_sha256"}
        }
        digest = _digest(event.get("event_sha256"), "review call event")
        if (
            digest != canonical_sha256_v3(event_core)
            or event.get("event_id") != f"machine-call:{digest}"
        ):
            _fail("review-frontier call event hash is stale")
        event_ids.append(str(event["event_id"]))
        _validate_structural_interface_candidates(
            event.get("structural_interface_candidates")
        )
    event_order = [
        (
            int(_mapping(row["call"], "review call")["instruction_rva"]),
            int(row["event_index"]),
            str(row["event_id"]),
        )
        for row in events
    ]
    if event_order != sorted(event_order) or len(event_ids) != len(set(event_ids)):
        _fail("review-frontier call events are noncanonical")

    writes = _rows(value.get("memory_write_effects"), "review write effects")
    for write in writes:
        if set(write) != {
            "transfer_id", "source", "effect", "expression_nodes",
            "effect_sha256",
        }:
            _fail("review-frontier write effect fields are malformed")
        _review_source(write.get("source"), "review write source")
        _review_expressions(
            write.get("expression_nodes"), "review write expressions"
        )
        effect = _mapping(write.get("effect"), "review write effect")
        if effect.get("op") != "memory_write":
            _fail("review-frontier write effect is not a memory write")
        write_core = {
            key: item for key, item in write.items()
            if key != "effect_sha256"
        }
        if _digest(
            write.get("effect_sha256"), "review write effect"
        ) != canonical_sha256_v3(write_core):
            _fail("review-frontier write effect hash is stale")

    outcomes = _rows(value.get("control_outcomes"), "review outcomes")
    for outcome in outcomes:
        if set(outcome) != {
            "transfer_id", "source", "terminator", "expression_nodes",
            "outcome_sha256",
        }:
            _fail("review-frontier outcome fields are malformed")
        _review_source(outcome.get("source"), "review outcome source")
        _review_expressions(
            outcome.get("expression_nodes"), "review outcome expressions"
        )
        if not isinstance(outcome.get("transfer_id"), str):
            _fail("review-frontier outcome transfer is malformed")
        _mapping(outcome.get("terminator"), "review terminator")
        outcome_core = {
            key: item for key, item in outcome.items()
            if key != "outcome_sha256"
        }
        if _digest(
            outcome.get("outcome_sha256"), "review outcome"
        ) != canonical_sha256_v3(outcome_core):
            _fail("review-frontier outcome hash is stale")

    candidates = _rows(
        value.get("lexical_service_candidates"), "review lexical candidates"
    )
    candidate_order = []
    for candidate in candidates:
        if set(candidate) != {
            "service_id", "rank", "confidence", "event_id", "identity",
            "authority",
        } or (
            candidate.get("authority") is not False
            or candidate.get("confidence")
            != "exact_normalized_import_name_only"
            or candidate.get("rank") != 1
            or candidate.get("service_id") not in declared
            or candidate.get("event_id") not in event_ids
        ):
            _fail("review-frontier lexical candidate is malformed")
        identity = _mapping(candidate.get("identity"), "review lexical identity")
        if set(identity) != {"dll", "symbol", "ordinal"}:
            _fail("review-frontier lexical identity fields are malformed")
        candidate_order.append((
            str(candidate["service_id"]), str(candidate["event_id"]),
        ))
    if candidate_order != sorted(candidate_order):
        _fail("review-frontier lexical candidates are noncanonical")

    counts = _mapping(value.get("counts"), "review-frontier counts")
    expected_counts = {
        "transfers": len(outcomes),
        "call_events": len(events),
        "named_external_calls": sum(
            _mapping(row["call"], "review call").get("kind")
            == "external_call" for row in events
        ),
        "indirect_calls": sum(
            _mapping(row["call"], "review call").get("kind")
            == "indirect_call" for row in events
        ),
        "internal_calls": sum(
            _mapping(row["call"], "review call").get("kind")
            == "internal_call" for row in events
        ),
        "memory_writes": len(writes),
        "control_outcomes": len(outcomes),
        "declared_services": len(declared),
        "mapped_services": len(mapped),
        "unmapped_services": len(unmapped),
        "lexical_candidates": len(candidates),
        "structural_interface_candidates": sum(
            len(_rows(
                row.get("structural_interface_candidates"),
                "review structural interface candidates",
            ))
            for row in events
        ),
        "structurally_classified_indirect_calls": sum(
            bool(_rows(
                row.get("structural_interface_candidates"),
                "review structural interface candidates",
            ))
            for row in events
        ),
    }
    if dict(counts) != expected_counts:
        _fail("review-frontier counts are stale")


def _validate_structural_interface_candidates(value: object) -> None:
    candidates = _rows(value, "review structural interface candidates")
    order = []
    identities: set[str] = set()
    for candidate in candidates:
        if set(candidate) != {
            "authority", "confidence", "admitted_domain_sha256",
            "method_contract_sha256", "profile_id", "profile_sha256",
            "interface_id", "method", "slot", "offset", "argument_words",
            "receiver_resource", "matching_declared_service_ids",
        } or (
            candidate.get("authority") is not False
            or candidate.get("confidence")
            != "exact_syntactic_vtable_slot_offset_only"
        ):
            _fail("review structural interface candidate is malformed")
        domain_sha256 = _digest(
            candidate.get("admitted_domain_sha256"),
            "review structural candidate domain",
        )
        method_sha256 = _digest(
            candidate.get("method_contract_sha256"),
            "review structural candidate method",
        )
        profile_sha256 = _digest(
            candidate.get("profile_sha256"),
            "review structural candidate profile",
        )
        slot = candidate.get("slot")
        offset = candidate.get("offset")
        argument_words = candidate.get("argument_words")
        receiver = _mapping(
            candidate.get("receiver_resource"),
            "review structural candidate receiver",
        )
        if (
            not isinstance(candidate.get("profile_id"), str)
            or not candidate["profile_id"]
            or not isinstance(candidate.get("interface_id"), str)
            or not candidate["interface_id"]
            or not isinstance(candidate.get("method"), str)
            or not candidate["method"]
            or not isinstance(slot, int) or isinstance(slot, bool) or slot < 0
            or offset != slot * 4
            or not isinstance(argument_words, int)
            or isinstance(argument_words, bool) or argument_words < 1
            or receiver.get("dispatch_slot") != slot
        ):
            _fail("review structural interface candidate fields are malformed")
        _canonical_text_ids(
            candidate.get("matching_declared_service_ids"),
            "structural candidate declared services",
        )
        if method_sha256 in identities:
            _fail("review structural interface candidates are duplicated")
        identities.add(method_sha256)
        order.append((
            profile_sha256, str(candidate["interface_id"]), int(slot),
            method_sha256, domain_sha256,
        ))
    if order != sorted(order):
        _fail("review structural interface candidates are noncanonical")


def _canonical_text_ids(value: object, context: str) -> list[str]:
    if (
        not isinstance(value, list)
        or any(not isinstance(item, str) or not item for item in value)
        or value != sorted(set(value))
    ):
        _fail(f"review-frontier {context} are noncanonical")
    return list(value)


def _review_source(value: object, context: str) -> Mapping[str, Any]:
    source = _mapping(value, context)
    if set(source) != {
        "contract_sha256", "instruction_bytes_sha256", "rva_end",
        "rva_start", "unit_ir_sha256",
    }:
        _fail(f"{context} fields are malformed")
    for field in (
        "contract_sha256", "instruction_bytes_sha256", "unit_ir_sha256",
    ):
        _digest(source.get(field), f"{context} {field}")
    if (
        not isinstance(source.get("rva_start"), int)
        or isinstance(source.get("rva_start"), bool)
        or not isinstance(source.get("rva_end"), int)
        or isinstance(source.get("rva_end"), bool)
        or source["rva_end"] <= source["rva_start"]
    ):
        _fail(f"{context} range is malformed")
    return source


def _review_expressions(value: object, context: str) -> None:
    expressions = _rows(value, context)
    ids = []
    for expression in expressions:
        if set(expression) != {
            "id", "op", "operands", "parameters", "result_sort", "width_bits",
        } or (
            not isinstance(expression.get("id"), int)
            or isinstance(expression.get("id"), bool)
            or expression["id"] < 0
            or not isinstance(expression.get("operands"), list)
        ):
            _fail(f"{context} contain a malformed node")
        ids.append(int(expression["id"]))
    if ids != sorted(set(ids)):
        _fail(f"{context} are noncanonical")
    known = set(ids)
    if any(
        not isinstance(item, int) or isinstance(item, bool) or item not in known
        for expression in expressions
        for item in expression["operands"]
    ):
        _fail(f"{context} are not dependency closed")


def _default_operation_symbols(
    bundle: CompiledComponentInterfaceV5,
) -> dict[str, str]:
    component = _identifier_fragment(bundle.interface.identity)
    return {
        operation.identity: (
            f"spx_component_{component}_{_identifier_fragment(operation.identity)}"
        )
        for operation in bundle.interface.operations
    }


def _render_public_header(
    bundle: CompiledComponentInterfaceV5, symbols: Mapping[str, str]
) -> str:
    from .atomics import spx_atomics_header
    from .component_c_v5 import render_component_c_headers_v5

    headers = render_component_c_headers_v5(bundle, symbols)
    public = headers["portable-component.h"]
    if '#include "spx-atomics.h"' in public:
        public = public.replace('#include "spx-atomics.h"', spx_atomics_header())
    # A writable package exposes the same context/view ABI used when its source
    # is installed. Inline its dependencies to retain the two-file package.
    return headers["portable-component-implementation.h"].replace(
        '#include "portable-component.h"', public)


def _render_operation_skeleton(
    bundle: CompiledComponentInterfaceV5,
    symbols: Mapping[str, str],
    semantic_slice_sha256: str,
) -> str:
    lines = [
        '#include "component.h"',
        "",
        '#error "replace generated operation skeletons with authored component C"',
        "",
    ]
    for operation in bundle.interface.operations:
        lines.extend([
            f"/* operation {operation.identity}: implement symbol "
            f"{symbols[operation.identity]} */",
            f"/* semantic slice {semantic_slice_sha256} */",
            "",
        ])
    return "\n".join(lines)


def _identifier_fragment(value: str) -> str:
    result = re.sub(r"[^A-Za-z0-9_]", "_", value)
    return result if result and not result[0].isdigit() else f"spx_{result}"


__all__ = [
    "ComponentWorkPackageV6", "ComponentWorkPackageV6Error",
    "build_component_semantic_slice_v2", "build_component_work_package_v6",
    "write_component_semantic_slice_v2",
]

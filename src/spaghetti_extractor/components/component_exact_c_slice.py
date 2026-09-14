"""Render a proof-scoped exact Behavioral-C slice from checked transfers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Mapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3
from .binding_intent import ComponentMachineBindingIntentV1
from .bisimulation import (
    ComponentBisimulationError,
    ComponentBisimulationIntentV1,
    load_component_bisimulation_intent,
)
from .formats import COMPONENT_EXACT_C_SLICE_V1_FORMAT
from ..transfer.behavioral_c_layout import build_behavioral_c_plan
from ..transfer.behavioral_c_model import BehavioralCLayoutIntent
from ..transfer.behavioral_c_render import (
    behavioral_c_header,
    behavioral_c_translation_units,
)
from ..transfer.model import _Transfer
from ..transfer.plan import load_executable_transfer_plan
from ..transfer.runtime_abi import exact_runtime_header
from ..util import sha256_file, write_json


def write_component_exact_c_slice_v1(
    *,
    component_id: str,
    transfers: Sequence[_Transfer],
    operations: Sequence[Mapping[str, object]],
    intent: ComponentBisimulationIntentV1 | None,
    executable_transfer_plan_sha256: str,
    out: Path,
    dependency_components: Sequence[Mapping[str, object]] = (),
) -> dict[str, object]:
    """Render the exact transfers for one component and its call closure."""

    effective_intent = intent
    if effective_intent is None:
        operation_ids = [
            str(operation.get("operation_id", "")) for operation in operations
        ]
        if (
            not operation_ids
            or any(not operation_id for operation_id in operation_ids)
            or len(operation_ids) != len(set(operation_ids))
        ):
            raise ComponentBisimulationError(
                "component exact-C slice cannot synthesize a bisimulation intent "
                "without unique operation identities"
            )
        effective_intent = ComponentBisimulationIntentV1.create(
            component_id=component_id,
            operations=[
                {"operation_id": operation_id, "syncs": []}
                for operation_id in sorted(operation_ids)
            ],
        )

    transfer_index = {item.identity: item for item in transfers}
    transfer_index_by_rva = {item.rva_start: item for item in transfers}
    if len(transfer_index) != len(transfers) or len(transfer_index_by_rva) != len(
        transfers
    ):
        raise ComponentBisimulationError(
            "component exact-C slice received duplicate transfer identities or RVAs"
        )
    root_unit_ids = sorted(
        {
            unit_id
            for operation in operations
            for unit_id in _string_rows(operation.get("unit_ids"), "operation units")
        }
    )
    root_context_unit_ids = sorted(
        {
            unit_id
            for operation in operations
            for unit_id in _string_rows(
                operation.get("context_unit_ids", operation.get("unit_ids")),
                "operation context units",
            )
        }
    )
    if not set(root_unit_ids) <= set(root_context_unit_ids):
        raise ComponentBisimulationError(
            "component exact-C context omits an owned root unit"
        )
    root_entries = sorted(
        {
            rva
            for operation in operations
            for rva in _uint_rows(operation.get("entry_rvas"), "operation entries")
        }
    )
    dependencies: list[dict[str, object]] = []
    dependency_ids: set[str] = set()
    for raw in dependency_components:
        row = _mapping(raw, "exact-C dependency component")
        dependency_id = str(row.get("component_id", ""))
        binding_sha256 = str(row.get("binding_intent_sha256", ""))
        dependency_operations = _mapping_rows(
            row.get("operations"), "exact-C dependency operations"
        )
        if (
            not dependency_id
            or dependency_id == component_id
            or dependency_id in dependency_ids
            or len(binding_sha256) != 64
        ):
            raise ComponentBisimulationError(
                "component exact-C dependency identity is malformed or duplicated"
            )
        dependency_ids.add(dependency_id)
        dependency_unit_ids = sorted(
            {
                unit_id
                for operation in dependency_operations
                for unit_id in _string_rows(
                    operation.get("unit_ids"), "dependency operation units"
                )
            }
        )
        dependency_entries = sorted(
            {
                rva
                for operation in dependency_operations
                for rva in _uint_rows(
                    operation.get("entry_rvas"), "dependency operation entries"
                )
            }
        )
        if not dependency_unit_ids or not dependency_entries:
            raise ComponentBisimulationError(
                "component exact-C dependency has no units or entries"
            )
        dependencies.append(
            {
                "component_id": dependency_id,
                "binding_intent_sha256": binding_sha256,
                "unit_ids": dependency_unit_ids,
                "entry_rvas": dependency_entries,
            }
        )
    dependencies.sort(key=lambda row: str(row["component_id"]))
    unit_ids = sorted(
        set(root_context_unit_ids)
        | {
            str(unit_id)
            for dependency in dependencies
            for unit_id in dependency["unit_ids"]
        }
    )
    missing = sorted(set(unit_ids) - set(transfer_index))
    if missing:
        raise ComponentBisimulationError(
            f"component exact-C slice misses checked transfers: {missing!r}"
        )
    call_closure = _internal_direct_call_closure(
        transfers=transfers,
        seed_unit_ids=unit_ids,
    )
    rendered_unit_ids = sorted(
        set(unit_ids)
        | set(
            _string_rows(
                call_closure.get("unit_ids"),
                "internal direct-call closure units",
            )
        )
    )
    selected = tuple(transfer_index[unit_id] for unit_id in rendered_unit_ids)
    entries = sorted(
        set(root_entries)
        | {
            int(rva)
            for dependency in dependencies
            for rva in dependency["entry_rvas"]
        }
    )
    sync_units = {
        sync.exact_unit_id
        for operation in effective_intent.operations
        for sync in operation.syncs
    }
    unknown_syncs = sorted(sync_units - set(unit_ids))
    if unknown_syncs:
        raise ComponentBisimulationError(
            f"component exact-C sync units are outside the proof slice: {unknown_syncs!r}"
        )
    continuation_units = {
        unit for operation in operations
        for unit in _string_rows(operation.get("continuation_unit_ids", []), "continuation units")
    }
    if continuation_units - set(root_context_unit_ids) or continuation_units & set(root_unit_ids):
        raise ComponentBisimulationError("exact-C continuations must be unowned declared proof context")
    forced_rvas = sorted(transfer_index[item].rva_start for item in sync_units | continuation_units)
    plan = build_behavioral_c_plan(
        selected,
        entry_rvas=entries,
        intent=BehavioralCLayoutIntent(forced_labels=tuple(forced_rvas)),
    )
    files, source_map = behavioral_c_translation_units(selected, plan)
    files["behavioral-c.h"] = behavioral_c_header(plan)
    files["state-machine-runtime.h"] = exact_runtime_header()
    output = Path(out)
    output.mkdir(parents=True, exist_ok=True)
    rows = []
    for name, content in sorted(files.items()):
        path = output / name
        path.write_text(content, encoding="ascii")
        rows.append({"path": name, "sha256": sha256_file(path)})
    source_rows = [
        {
            "unit_id": transfer_index_by_rva[selected_rva].identity,
            **dict(row),
        }
        for selected_rva, row in sorted(source_map.items())
    ]
    core: dict[str, object] = {
        "format": COMPONENT_EXACT_C_SLICE_V1_FORMAT,
        "component_id": component_id,
        "bindings": {
            "executable_transfer_plan_sha256": executable_transfer_plan_sha256,
            "bisimulation_intent_sha256": effective_intent.intent_sha256,
            "dependency_binding_intent_sha256s": {
                str(row["component_id"]): str(row["binding_intent_sha256"])
                for row in dependencies
            },
        },
        "root_unit_ids": root_unit_ids,
        "root_context_unit_ids": root_context_unit_ids,
        "root_entry_rvas": root_entries,
        "dependency_components": dependencies,
        "internal_direct_call_closure": call_closure,
        "unit_ids": unit_ids,
        "entry_rvas": entries,
        "forced_label_rvas": forced_rvas,
        "functions": [item.payload() for item in plan.functions],
        "source_map": source_rows,
        "files": rows,
        "policy": {
            "exact_checked_transfers_only": True,
            "connected_component_closure_bound": True,
            "forced_labels_are_step_barriers": True,
            "production_run_semantics_preserved": True,
        },
    }
    manifest = {**core, "slice_sha256": canonical_sha256_v3(core)}
    write_json(output / "component-exact-c-slice-v1.json", manifest)
    return manifest


def _internal_direct_call_closure(
    *,
    transfers: Sequence[_Transfer],
    seed_unit_ids: Sequence[str],
) -> dict[str, object]:
    """Close checked constant direct calls without changing component ownership.

    The seed units are already authorized root context or connected-component
    dependencies.  Units reached only while executing a direct callee are
    proof context: they are rendered into the exact model, but remain separate
    from the component's deployment-owned ``unit_ids``.
    """

    by_id = {item.identity: item for item in transfers}
    by_rva = {item.rva_start: item for item in transfers}
    if len(by_id) != len(transfers) or len(by_rva) != len(transfers):
        raise ComponentBisimulationError(
            "component exact-C call closure received duplicate transfer "
            "identities or RVAs"
        )
    seeds = set(seed_unit_ids)
    missing_seeds = sorted(seeds - set(by_id))
    if missing_seeds:
        raise ComponentBisimulationError(
            "component exact-C call closure misses checked seed transfers: "
            f"{missing_seeds!r}"
        )

    selected = set(seeds)
    closure_units: set[str] = set()
    closure_entries: set[int] = set()
    call_edges: set[tuple[str, int, int, int, str, int, int]] = set()
    call_pending = list(sorted(seeds, reverse=True))
    control_pending: list[str] = []
    calls_checked: set[str] = set()
    control_checked: set[str] = set()

    while call_pending or control_pending:
        while call_pending:
            unit_id = call_pending.pop()
            if unit_id in calls_checked:
                continue
            calls_checked.add(unit_id)
            transfer = by_id[unit_id]
            for call in transfer.calls:
                if call.kind != "internal_call":
                    continue
                if call.target_node is not None:
                    raise ComponentBisimulationError(
                        f"{unit_id}: internal direct call has a computed target"
                    )
                target = by_rva.get(call.target_rva)
                if target is None:
                    raise ComponentBisimulationError(
                        f"{unit_id}: internal direct-call target "
                        f"0x{call.target_rva:08x} is absent from the checked "
                        "transfer plan"
                    )
                closure_entries.add(target.rva_start)
                call_edges.add(
                    (
                        unit_id,
                        transfer.rva_start,
                        call.instruction_rva,
                        call.call_index,
                        target.identity,
                        target.rva_start,
                        call.return_rva,
                    )
                )
                if target.identity not in selected:
                    selected.add(target.identity)
                    closure_units.add(target.identity)
                    call_pending.append(target.identity)
                control_pending.append(target.identity)

        while control_pending:
            unit_id = control_pending.pop()
            if unit_id in control_checked:
                continue
            control_checked.add(unit_id)
            transfer = by_id[unit_id]
            for successor_rva in _direct_control_successor_rvas(transfer):
                successor = by_rva.get(successor_rva)
                if successor is None:
                    raise ComponentBisimulationError(
                        f"{unit_id}: direct-call closure control target "
                        f"0x{successor_rva:08x} is absent from the checked "
                        "transfer plan"
                    )
                if successor.identity not in selected:
                    selected.add(successor.identity)
                    closure_units.add(successor.identity)
                    call_pending.append(successor.identity)
                control_pending.append(successor.identity)

    return {
        "unit_ids": sorted(closure_units),
        "entry_rvas": sorted(closure_entries),
        "call_edges": [
            {
                "source_unit_id": source_unit_id,
                "source_rva": source_rva,
                "instruction_rva": instruction_rva,
                "call_index": call_index,
                "target_unit_id": target_unit_id,
                "target_rva": target_rva,
                "return_rva": return_rva,
            }
            for (
                source_unit_id,
                source_rva,
                instruction_rva,
                call_index,
                target_unit_id,
                target_rva,
                return_rva,
            ) in sorted(call_edges)
        ],
    }


def _direct_control_successor_rvas(transfer: _Transfer) -> tuple[int, ...]:
    if not transfer.actions:
        raise ComponentBisimulationError(
            f"{transfer.identity}: checked transfer has no terminal action"
        )
    outcome = transfer.actions[-1]
    if outcome.op in {"outcome_fallthrough", "outcome_jump"}:
        return tuple(outcome.args[:1])
    if outcome.op == "outcome_branch":
        return tuple(outcome.args[1:3])
    if outcome.op in {
        "outcome_return",
        "outcome_indirect",
        "outcome_nonlocal",
        "outcome_external",
    }:
        return ()
    raise ComponentBisimulationError(
        f"{transfer.identity}: final action {outcome.op!r} is not an outcome"
    )


def materialize_component_exact_c_slice_v1(
    *,
    transfer_plan: Path,
    binding_intent: Path,
    dependency_binding_intents: Mapping[str, Path] | None = None,
    bisimulation_intent: Path | None,
    out: Path,
) -> dict[str, object]:
    """Load the three content-addressed inputs and materialize one slice."""

    _payload, transfers = load_executable_transfer_plan(
        Path(transfer_plan), require_complete=False
    )
    binding = ComponentMachineBindingIntentV1.parse(
        _load_json(Path(binding_intent), "component machine-binding intent")
    )
    intent = (
        None
        if bisimulation_intent is None
        else load_component_bisimulation_intent(Path(bisimulation_intent))
    )
    if intent is not None and intent.component_id != binding.component_id:
        raise ComponentBisimulationError("exact-C slice inputs name different components")
    operations = [
        {
            "operation_id": operation.semantics.operation_id,
            "unit_ids": list(operation.semantics.unit_ids),
            # The replacement may summarize the declared exit transfer (for
            # example, a compiler-generated scalar return epilogue).  Retain
            # that unchanged machine context on the exact side so the proof
            # compares complete operation outcomes, while root_unit_ids keeps
            # the actual deployment ownership narrow.
            "context_unit_ids": list(operation.semantics.transfer_ids),
            "continuation_unit_ids": list(operation.semantics.machine_projection.get("operation", {}).get("continuation_unit_ids", [])),
            "entry_rvas": list(operation.semantics.entry_rvas),
        }
        for operation in binding.operations
    ]
    dependency_components: list[dict[str, object]] = []
    for dependency_id, dependency_path in sorted(
        (dependency_binding_intents or {}).items()
    ):
        dependency = ComponentMachineBindingIntentV1.parse(
            _load_json(
                Path(dependency_path),
                f"dependency {dependency_id} component machine-binding intent",
            )
        )
        if dependency.component_id != dependency_id:
            raise ComponentBisimulationError(
                "exact-C dependency key names another component"
            )
        dependency_components.append(
            {
                "component_id": dependency.component_id,
                "binding_intent_sha256": dependency.intent_sha256,
                "operations": [
                    {
                        # A root proof stops at its declared operation exit,
                        # but a connected callee must execute through that
                        # exit and return to its caller.
                        "unit_ids": list(operation.semantics.transfer_ids),
                        "entry_rvas": list(operation.semantics.entry_rvas),
                    }
                    for operation in dependency.operations
                ],
            }
        )
    return write_component_exact_c_slice_v1(
        component_id=binding.component_id,
        transfers=transfers,
        operations=operations,
        intent=intent,
        executable_transfer_plan_sha256=sha256_file(Path(transfer_plan)),
        out=Path(out),
        dependency_components=dependency_components,
    )


def _load_json(path: Path, context: str) -> Mapping[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ComponentBisimulationError(f"cannot read {context}: {exc}") from exc
    if not isinstance(value, Mapping):
        raise ComponentBisimulationError(f"{context} must be an object")
    return value


def _mapping(value: object, context: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ComponentBisimulationError(f"{context} must be an object")
    return value


def _mapping_rows(value: object, context: str) -> list[Mapping[str, object]]:
    if not isinstance(value, list) or any(not isinstance(item, Mapping) for item in value):
        raise ComponentBisimulationError(f"{context} must be an array of objects")
    return list(value)


def _string_rows(value: object, context: str) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ComponentBisimulationError(f"{context} must be an array of strings")
    return list(value)


def _uint_rows(value: object, context: str) -> list[int]:
    if not isinstance(value, list) or any(
        not isinstance(item, int) or isinstance(item, bool) or item < 0
        for item in value
    ):
        raise ComponentBisimulationError(f"{context} must be unsigned integers")
    return list(value)


__all__ = [
    "materialize_component_exact_c_slice_v1",
    "write_component_exact_c_slice_v1",
]

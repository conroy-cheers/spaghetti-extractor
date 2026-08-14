"""Deterministic reconstruction planning over checked machine IR."""

from __future__ import annotations

import copy
import json
from collections import Counter
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any, Mapping, Sequence

from .artifact_formats import RECONSTRUCTION_PLAN_FORMAT
from .machine_import_profiles import load_machine_import_profile_set
from .reconstruction_contract_analysis import analyze_reconstruction_contracts
from .reconstruction_composition import (
    canonical_composition_sha256,
    compose_linear_reconstruction_cluster,
    inspect_linear_reconstruction_cluster,
)
from .reconstruction_control import propose_semantic_clusters
from .reconstruction_ir import (
    MACHINE_IR_FILENAME,
    MACHINE_IR_FORMAT,
    MACHINE_IR_MANIFEST_FILENAME,
)
from .stage_binary import StageAInputError
from .util import sha256_file, write_json


_REGISTERS = ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
_FLAGS = ("cf", "zf", "sf", "of", "pf", "df")
_SUPPORTED_TEMPLATES = frozenset(
    {"compare_branch", "constant_external_call", "store_then_zero_call"}
)


@dataclass(frozen=True)
class MachineIRInput:
    root: Path
    manifest_path: Path
    machine_ir_path: Path
    manifest: Mapping[str, Any]
    units: tuple[Mapping[str, Any], ...]
    machine_ir_sha256: str


def write_reconstruction_plan(
    *,
    machine_ir: Path,
    out: Path,
    signature_catalog: Path | Mapping[str, Any] | Sequence[Any] | None = None,
) -> dict[str, Any]:
    """Emit deterministic, one-entry work clusters from a machine-IR package."""

    package = _load_machine_ir(machine_ir)
    normalized_signature_catalog = _load_signature_catalog(signature_catalog)
    by_rva = {int(_source_span(unit)["rva_start"]): unit for unit in package.units}
    by_id = {str(unit["id"]): unit for unit in package.units}
    predecessors: Counter[int] = Counter()
    for unit in package.units:
        for target in _direct_targets(unit):
            predecessors[target] += 1

    graph = _plan_control_graph(package)
    recovered_by_source = {
        str(item["source_unit_id"]): item
        for item in graph["recovered_indirect_targets"]
        if item.get("status") == "recovered"
    }
    clusters = []
    for proposal in graph["clusters"]:
        member_units = sorted(
            (by_id[unit_id] for unit_id in proposal["unit_ids"]),
            key=lambda item: (int(_source_span(item)["rva_start"]), str(item["id"])),
        )
        entry_candidates = sorted(
            (by_id[unit_id] for unit_id in proposal["entry_unit_ids"]),
            key=lambda item: (int(_source_span(item)["rva_start"]), str(item["id"])),
        )
        unit = entry_candidates[0]
        template, template_dependencies, reason = _select_template(unit, by_rva)
        if len(member_units) != 1 and template is not None:
            template = None
            reason = (
                "the discovered semantic cluster has multiple units and no reviewed "
                "cluster-wide portable template"
            )
        entry_rva = int(_source_span(unit)["rva_start"])
        category = (
            "loop" if proposal["kind"] == "loop_scc" else _category(unit)
        )
        if len(member_units) == 1:
            composition = {
                "status": "not_required",
                "kind": "single_unit",
                "entry_unit_id": str(unit["id"]),
                "unit_ids": [str(unit["id"])],
                "unit_entry_rvas": [entry_rva],
                "issues": [],
            }
            semantic_units = member_units
        else:
            composition = inspect_linear_reconstruction_cluster(
                member_units, entry_unit_id=str(unit["id"])
            )
            semantic_units = member_units
        expressions = _semantic_expressions(semantic_units)
        inputs = _value_inputs(expressions)
        outputs = _value_outputs(semantic_units)
        memory = _memory_inventory(semantic_units)
        events = _event_inventory(semantic_units, include_internal=False)
        contract_analysis = analyze_reconstruction_contracts(
            semantic_units,
            normalized_signature_catalog,
            cluster_id=str(proposal["id"]),
        )
        control_contract = _cluster_control_contract(
            member_units, by_rva, recovered_by_source
        )
        blockers = []
        if template is None:
            blockers.append(
                {
                    "code": "no_portable_template",
                    "message": reason,
                    "next_action": (
                        "author a typed implementation and generated adapter, or add a "
                        "generic semantics-driven template for this shape"
                    ),
                }
            )
        unresolved_indirect = [
            item for item in member_units
            if bool(item.get("control", {}).get("has_indirect_target"))
            and str(item["id"]) not in recovered_by_source
        ]
        if unresolved_indirect:
            blockers.append(
                {
                    "code": "indirect_target_boundary",
                    "message": "the cluster has an indirect exit without a finite checked inventory",
                    "next_action": "close the path-sensitive target inventory before promotion",
                }
            )
        if len(entry_candidates) != 1:
            blockers.append(
                {
                    "code": "multiple_cluster_entries",
                    "message": "the proposed cluster has multiple externally reachable entries",
                    "next_action": "split at the entry cutpoints or author a multi-entry adapter",
                }
            )
        if len(member_units) > 1 and composition["status"] != "complete":
            blockers.append(
                {
                    "code": "uncomposed_cluster_semantics",
                    "message": (
                        "the multi-unit cluster has no checked finite linear composition: "
                        + ", ".join(
                            str(item.get("code", "unknown"))
                            for item in composition.get("issues", [])
                        )
                    ),
                    "next_action": (
                        "split the cluster or add a path/invariant composer for its control shape"
                    ),
                }
            )
        if contract_analysis["status"] != "complete":
            blockers.append(
                {
                    "code": "incomplete_typed_contract",
                    "message": (
                        f"typed memory/API/atomic analysis has "
                        f"{contract_analysis['counts']['issues']} unresolved issue(s)"
                    ),
                    "next_action": "resolve the named analysis issues or provide checked type/ABI guidance",
                }
            )
        if any(item.get("status") != "qualified" for item in member_units):
            blockers.append(
                {
                    "code": "unqualified_machine_ir",
                    "message": "one or more cluster units are not qualified machine IR",
                    "next_action": "close the Stage A machine-IR issue before source lifting",
                }
            )
        cluster_core = {
            "entry_unit_id": str(unit["id"]),
            "entry_rva": entry_rva,
            "unit_ids": sorted(str(item["id"]) for item in member_units),
            "unit_contract_sha256s": sorted(
                str(item["source"]["contract_sha256"]) for item in member_units
            ),
            "template": template,
            "discovery": proposal,
            "control": control_contract,
            "composition_sha256": canonical_composition_sha256(composition),
        }
        cluster_sha256 = _canonical_sha256(cluster_core)
        score = _work_score(
            template=template,
            unit_count=len(member_units),
            memory_count=len(memory),
            event_count=len(events),
            predecessor_count=predecessors[entry_rva],
            blockers=len(blockers),
        )
        clusters.append(
            {
                "id": f"cluster:{entry_rva:08x}:{cluster_sha256[:12]}",
                "contract_sha256": cluster_sha256,
                "entry_unit_id": str(unit["id"]),
                "entry_rva": entry_rva,
                "unit_ids": sorted(str(item["id"]) for item in member_units),
                "template_dependency_unit_ids": sorted(
                    str(by_rva[rva]["id"])
                    for rva in template_dependencies
                    if rva in by_rva and by_rva[rva] not in member_units
                ),
                "rva_spans": sorted(
                    [
                    {
                        "start": int(_source_span(item)["rva_start"]),
                        "end": int(_source_span(item)["rva_end"]),
                    }
                    for item in member_units
                    ],
                    key=lambda span: (span["start"], span["end"]),
                ),
                "category": category,
                "template": template,
                "template_reason": reason,
                "portable_source_ready": template in _SUPPORTED_TEMPLATES,
                "reachable": any(
                    _unit_reachability(item) == "reachable" for item in member_units
                ),
                "potentially_reachable": any(
                    _unit_reachability(item) == "potential" for item in member_units
                ),
                "reachability": sorted(
                    {_unit_reachability(item) for item in member_units}
                ),
                "discovery": copy.deepcopy(proposal),
                "predecessor_count": predecessors[entry_rva],
                "inputs": inputs,
                "outputs": outputs,
                "memory": memory,
                "external_events": events,
                "control": control_contract,
                "composition": composition,
                "typed_contract": contract_analysis,
                "validation_requirements": _validation_requirements(
                    semantic_units, contract_analysis, recovered_by_source
                ),
                "blockers": blockers,
                "work_score": score,
                "source": {
                    "machine_ir_sha256": package.machine_ir_sha256,
                    "unit_contract_sha256s": cluster_core[
                        "unit_contract_sha256s"
                    ],
                },
            }
        )

    clusters.sort(
        key=lambda item: (
            not bool(item["reachable"]),
            not bool(item["potentially_reachable"]),
            bool(item["blockers"]),
            int(item["work_score"]),
            int(item["entry_rva"]),
        )
    )
    counts = Counter(str(item["category"]) for item in clusters)
    templates = Counter(str(item["template"] or "unsupported") for item in clusters)
    payload = {
        "format": RECONSTRUCTION_PLAN_FORMAT,
        "status": "qualified" if package.manifest.get("status") == "qualified" else "incomplete",
        "executes_original_binary": False,
        "inputs": {
            "machine_ir": {
                "format": package.manifest.get("format"),
                "sha256": package.machine_ir_sha256,
                "manifest_sha256": sha256_file(package.manifest_path),
            },
            "signature_catalog": _signature_catalog_binding(signature_catalog),
        },
        "policy": {
            "unit_of_work": "disjoint cutpoint-bounded semantic cluster",
            "portable_logic_owns": "typed values, data transformations, and service calls",
            "generated_adapter_owns": "x86 registers, flags, guest memory, and control exits",
            "manual_guidance_allowed": True,
            "original_runtime_access": "forbidden",
            "reachability_authority": "rooted decoded control graph",
        },
        "control_analysis": graph["summary"],
        "counts": {
            "clusters": len(clusters),
            "reachable_clusters": sum(bool(item["reachable"]) for item in clusters),
            "potentially_reachable_clusters": sum(
                bool(item["potentially_reachable"]) for item in clusters
            ),
            "portable_source_ready": sum(
                bool(item["portable_source_ready"]) for item in clusters
            ),
            "blocked": sum(bool(item["blockers"]) for item in clusters),
            "by_category": dict(sorted(counts.items())),
            "by_template": dict(sorted(templates.items())),
        },
        "clusters": clusters,
    }
    payload["plan_sha256"] = _canonical_sha256(payload)
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    write_json(out, payload)
    return payload


def _load_machine_ir(value: Path) -> MachineIRInput:
    value = Path(value)
    if value.is_dir():
        root = value
        manifest_path = root / MACHINE_IR_MANIFEST_FILENAME
        machine_ir_path = root / MACHINE_IR_FILENAME
    elif value.name == MACHINE_IR_MANIFEST_FILENAME:
        root = value.parent
        manifest_path = value
        machine_ir_path = root / MACHINE_IR_FILENAME
    elif value.name == MACHINE_IR_FILENAME:
        root = value.parent
        machine_ir_path = value
        manifest_path = root / MACHINE_IR_MANIFEST_FILENAME
    else:
        raise StageAInputError(
            "machine IR input must be a package directory, manifest, or JSONL data file"
        )
    if not manifest_path.is_file() or not machine_ir_path.is_file():
        raise StageAInputError("machine IR package requires its manifest and JSONL data")
    manifest = _read_object(manifest_path, "machine IR manifest")
    _require_format(manifest, MACHINE_IR_FORMAT, "machine IR manifest")
    units = []
    for number, raw in enumerate(machine_ir_path.read_text(encoding="utf-8").splitlines(), 1):
        if not raw:
            continue
        try:
            unit = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise StageAInputError(f"machine IR line {number} is invalid JSON: {exc}") from exc
        if not isinstance(unit, dict) or unit.get("record_kind") != "unit":
            raise StageAInputError(f"machine IR line {number} is not a unit record")
        units.append(unit)
    if not units:
        raise StageAInputError("machine IR contains no units")
    return MachineIRInput(
        root=root,
        manifest_path=manifest_path,
        machine_ir_path=machine_ir_path,
        manifest=manifest,
        units=tuple(units),
        machine_ir_sha256=sha256_file(machine_ir_path),
    )


def _load_signature_catalog(
    value: Path | Mapping[str, Any] | Sequence[Any] | None,
) -> Mapping[str, Any] | Sequence[Any] | None:
    if value is None or isinstance(value, Mapping):
        return value
    if isinstance(value, Sequence) and not isinstance(
        value, (str, bytes, bytearray, Path)
    ):
        return value
    path = Path(value)
    selected = load_machine_import_profile_set([path]).contracts
    rows = []
    for contract in selected:
        row = copy.deepcopy(dict(contract.contract))
        row["import"] = {
            "dll": contract.identity.dll,
            contract.identity.kind: contract.identity.value,
        }
        row["profile_binding"] = {
            "profile_id": contract.profile_id,
            "profile_sha256": contract.profile_sha256,
            "entry_key": contract.entry_key,
            "entry_index": contract.entry_index,
        }
        rows.append(row)
    return {"entries": rows}


def _signature_catalog_binding(
    value: Path | Mapping[str, Any] | Sequence[Any] | None,
) -> dict[str, Any] | None:
    if value is None:
        return None
    if isinstance(value, (str, Path)):
        path = Path(value)
        profiles = load_machine_import_profile_set([path]).profiles
        return {
            "path": path.name,
            "sha256": sha256_file(path),
            "profiles": [
                {
                    "id": profile.profile_id,
                    "path": profile.path.name,
                    "sha256": profile.sha256,
                }
                for profile in profiles
            ],
        }
    return {"embedded_sha256": _canonical_sha256(value)}


def _plan_control_graph(package: MachineIRInput) -> dict[str, Any]:
    units = list(package.units)
    by_rva = {int(_source_span(unit)["rva_start"]): unit for unit in units}
    direct_edges: list[dict[str, Any]] = []
    internal_edges: list[dict[str, Any]] = []
    external_exits: list[dict[str, Any]] = []
    fault_exits: list[dict[str, Any]] = []
    indirect_exits: list[dict[str, Any]] = []
    for unit in units:
        source_id = str(unit["id"])
        for target in _direct_targets(unit):
            direct_edges.append(
                {
                    "source_unit_id": source_id,
                    "target_rva": target,
                    "target_unit_id": (
                        str(by_rva[target]["id"]) if target in by_rva else None
                    ),
                }
            )
        events = unit.get("semantics", {}).get("external_events", [])
        if isinstance(events, list):
            for event in events:
                if not isinstance(event, Mapping):
                    continue
                if event.get("kind") == "internal_call" and isinstance(
                    event.get("target_rva"), int
                ):
                    target = int(event["target_rva"])
                    internal_edges.append(
                        {
                            "source_unit_id": source_id,
                            "target_rva": target,
                            "target_unit_id": (
                                str(by_rva[target]["id"]) if target in by_rva else None
                            ),
                        }
                    )
                elif event.get("kind") == "external_call":
                    external_exits.append({"source_unit_id": source_id})
        if unit.get("semantics", {}).get("faults"):
            fault_exits.append({"source_unit_id": source_id})
        if bool(unit.get("control", {}).get("has_indirect_target")):
            indirect_exits.append({"source_unit_id": source_id})

    manifest_control = package.manifest.get("control")
    if not isinstance(manifest_control, Mapping):
        manifest_control = {}
    recovered = [
        copy.deepcopy(item)
        for item in manifest_control.get("recovered_indirect_targets", [])
        if isinstance(item, Mapping)
    ]
    reachability = manifest_control.get("reachability")
    exact = {
        str(unit["id"])
        for unit in units
        if _unit_reachability(unit) == "reachable"
    }
    potential = {
        str(unit["id"])
        for unit in units
        if _unit_reachability(unit) == "potential"
    }
    if isinstance(reachability, Mapping):
        exact = {
            str(unit_id) for unit_id in reachability.get("reachable_units", [])
        }
        potential = {
            str(unit_id) for unit_id in reachability.get("potential_units", [])
        }
    active = exact | potential
    if not active:
        active = {str(unit["id"]) for unit in units}
    roots = []
    for root in manifest_control.get("roots", []):
        if not isinstance(root, Mapping):
            continue
        rva = root.get("rva", root.get("target_rva"))
        if isinstance(rva, int) and rva in by_rva:
            roots.append(str(by_rva[rva]["id"]))
    proposed = propose_semantic_clusters(
        units=units,
        direct_edges=direct_edges,
        reachable_units=active,
        roots=roots,
        internal_call_edges=internal_edges,
        external_exits=external_exits,
        fault_exits=fault_exits,
        indirect_exits=indirect_exits,
    )
    return {
        "clusters": proposed["clusters"],
        "recovered_indirect_targets": recovered,
        "summary": {
            "status": proposed["status"],
            "reachability_status": (
                reachability.get("status")
                if isinstance(reachability, Mapping)
                else "legacy_unit_annotations"
            ),
            "exact_reachable_units": len(exact),
            "potential_units": len(potential),
            "frontiers": (
                copy.deepcopy(reachability.get("frontiers", []))
                if isinstance(reachability, Mapping)
                else []
            ),
            "cluster_counts": copy.deepcopy(proposed["counts"]),
            "issues": copy.deepcopy(proposed["issues"]),
        },
    }


def _unit_reachability(unit: Mapping[str, Any]) -> str:
    value = unit.get("reachability")
    if value in {"reachable", "potential", "unreachable"}:
        return str(value)
    return "reachable" if bool(unit.get("reachable")) else "unreachable"


def _select_template(
    unit: Mapping[str, Any], by_rva: Mapping[int, Mapping[str, Any]]
) -> tuple[str | None, tuple[int, ...], str]:
    entry = int(_source_span(unit)["rva_start"])
    semantics = _object(unit.get("semantics"), "unit semantics")
    events = _array(semantics.get("external_events"), "unit external events")
    if unit.get("control", {}).get("kind") == "branch" and _is_compare_branch(unit):
        return "compare_branch", (entry,), "recognized register comparison and two direct exits"
    if len(events) == 1 and events[0].get("kind") == "external_call" and _is_constant_external_call(unit):
        return "constant_external_call", (entry,), "recognized one-argument imported service call"
    if len(events) == 1 and events[0].get("kind") == "internal_call":
        target = events[0].get("target_rva")
        callee = by_rva.get(target) if isinstance(target, int) else None
        if callee is not None and _is_zero_return_callee(callee) and _is_store_before_call(unit):
            return "store_then_zero_call", (entry, int(target)), "recognized store followed by a zero-return helper"
    return None, (entry,), f"no reviewed portable template for {_category(unit)} semantics"


def _is_compare_branch(unit: Mapping[str, Any]) -> bool:
    instructions = _array(unit.get("instructions"), "unit instructions")
    semantics = unit.get("semantics", {})
    if (
        len(instructions) != 2
        or instructions[0].get("mnemonic") != "cmp"
        or instructions[1].get("mnemonic") not in {"je", "jz"}
        or semantics.get("register_writes") != []
        or semantics.get("memory_events") != []
        or semantics.get("external_events") != []
        or semantics.get("faults") != []
    ):
        return False
    operands = instructions[0].get("operands")
    if not (
        isinstance(operands, list) and len(operands) == 2
        and all(
            isinstance(item, dict)
            and item.get("kind") == "register"
            and item.get("width_bits", 32) == 32
            for item in operands
        )
    ):
        return False
    left, right = (str(operands[0]["name"]), str(operands[1]["name"]))
    difference = {"op": "sub32", "args": [_reg_expr(left), _reg_expr(right)]}
    condition = {"op": "eq", "args": [difference, {"op": "const", "value": 0, "width": 32}]}
    outcome = semantics.get("outcome", {})
    flag_writes = {item.get("flag"): item.get("value") for item in semantics.get("flag_writes", [])}
    return (
        set(flag_writes) == {"cf", "of", "pf", "sf", "zf"}
        and flag_writes["cf"] == {"op": "ult32", "args": [_reg_expr(left), _reg_expr(right)]}
        and flag_writes["pf"] == {"op": "parity", "args": [32, difference]}
        and flag_writes["sf"] == {"op": "msb", "args": [32, difference]}
        and flag_writes["zf"] == condition
        and isinstance(flag_writes["of"], dict)
        and flag_writes["of"].get("op") == "sub_overflow"
        and flag_writes["of"].get("args") == [32, _reg_expr(left), _reg_expr(right), difference]
        and outcome.get("kind") == "branch"
        and outcome.get("condition") == condition
        and isinstance(outcome.get("true_target_rva"), int)
        and isinstance(outcome.get("false_target_rva"), int)
    )


def _is_constant_external_call(unit: Mapping[str, Any]) -> bool:
    semantics = unit.get("semantics", {})
    events = semantics.get("external_events", [])
    memory = semantics.get("memory_events", [])
    if (
        len(events) != 1
        or events[0].get("kind") != "external_call"
        or len(events[0].get("stack_inputs", [])) != 1
        or len(events[0].get("arguments", [])) != 1
        or len(memory) != 1
        or semantics.get("faults") != []
        or semantics.get("outcome", {}).get("kind") != "fallthrough"
        or _bound_external_instruction_event(unit) is None
    ):
        return False
    stack = events[0]["stack_inputs"][0]
    value = stack.get("value")
    write = memory[0]
    expected_address = _stack_address_expr(int(stack.get("offset", 0)))
    response_registers = {
        item.get("register"): item.get("value")
        for item in semantics.get("register_writes", [])
    }
    response_flags = {
        item.get("flag"): item.get("value") for item in semantics.get("flag_writes", [])
    }
    return (
        isinstance(value, dict) and value.get("op") == "const"
        and write == {"kind": "write", "address": expected_address, "width": 4, "value": value}
        and events[0]["arguments"][0] == {"op": "load", "address": expected_address, "width": 4}
        and set(response_registers) == set(_REGISTERS)
        and all(
            response_registers[name]
            == {"op": "call_response", "call_index": 0, "register": name, "width": 32}
            for name in _REGISTERS
        )
        and set(response_flags) == set(_FLAGS)
        and all(
            response_flags[name] == {"op": "call_flag", "call_index": 0, "flag": name}
            for name in _FLAGS
        )
    )


def _bound_external_instruction_event(
    unit: Mapping[str, Any],
) -> Mapping[str, Any] | None:
    """Return the unique external event bound to its exact call instruction."""
    semantics = unit.get("semantics")
    if not isinstance(semantics, Mapping):
        return None
    external_events = semantics.get("external_events")
    ordered_events = semantics.get("ordered_events")
    if not isinstance(external_events, list) or len(external_events) != 1:
        return None
    if not isinstance(ordered_events, list):
        return None
    event = external_events[0]
    if not isinstance(event, Mapping):
        return None
    ordered_external = [
        candidate
        for candidate in ordered_events
        if isinstance(candidate, Mapping)
        and candidate.get("family") == "external"
        and candidate.get("kind") == "external_call"
    ]
    if len(ordered_external) != 1:
        return None
    bound = ordered_external[0]
    if any(
        bound.get(field) != event.get(field)
        for field in ("dll", "symbol", "ordinal", "return_rva")
    ):
        return None
    instruction_rva = bound.get("instruction_rva")
    if not isinstance(instruction_rva, int):
        return None
    span = _source_span(unit)
    if not int(span["rva_start"]) <= instruction_rva < int(span["rva_end"]):
        return None
    matching_instructions = [
        instruction
        for instruction in unit.get("instructions", [])
        if isinstance(instruction, Mapping)
        and instruction.get("rva_start") == instruction_rva
        and instruction.get("mnemonic") == "call"
    ]
    if len(matching_instructions) != 1:
        return None
    return bound


def _is_zero_return_callee(unit: Mapping[str, Any]) -> bool:
    semantics = unit.get("semantics", {})
    writes = {item.get("register"): item.get("value") for item in semantics.get("register_writes", [])}
    eax = writes.get("eax")
    flag_writes = {item.get("flag"): item.get("value") for item in semantics.get("flag_writes", [])}
    return (
        semantics.get("outcome", {}).get("kind") == "return"
        and isinstance(eax, dict)
        and eax.get("op") == "const"
        and eax.get("value") == 0
        and set(writes) == {"eax", "esp"}
        and writes["esp"]
        == {"op": "add32", "args": [{"op": "const", "value": 4, "width": 32}, _reg_expr("esp")]}
        and flag_writes.get("cf") == {"op": "false"}
        and flag_writes.get("of") == {"op": "false"}
        and flag_writes.get("sf", {}).get("op") == "msb"
        and flag_writes.get("zf", {}).get("op") == "eq"
        and flag_writes.get("pf", {}).get("op") == "parity"
        and semantics.get("external_events") == []
        and semantics.get("faults") == []
        and semantics.get("memory_events")
        == [{"kind": "read", "address": _reg_expr("esp"), "width": 4}]
    )


def _is_store_before_call(unit: Mapping[str, Any]) -> bool:
    semantics = unit.get("semantics", {})
    memory = semantics.get("memory_events", [])
    calls = semantics.get("external_events", [])
    if len(memory) != 2 or len(calls) != 1 or calls[0].get("kind") != "internal_call":
        return False
    read, write = memory
    if (
        read.get("kind") != "read" or read.get("width") != 4
        or not isinstance(read.get("address"), dict)
        or read["address"].get("op") != "const"
        or write.get("kind") != "write" or write.get("width") != 4
        or write.get("address", {}).get("op") != "reg"
        or write.get("value") != {"op": "load", "address": read["address"], "width": 4}
        or semantics.get("faults") != []
        or semantics.get("outcome", {}).get("kind") != "fallthrough"
    ):
        return False
    call_inputs = calls[0].get("register_inputs", {})
    if call_inputs.get("edx") != write["value"]:
        return False
    response_registers = {
        item.get("register"): item.get("value") for item in semantics.get("register_writes", [])
    }
    response_flags = {
        item.get("flag"): item.get("value") for item in semantics.get("flag_writes", [])
    }
    return (
        set(response_registers) == set(_REGISTERS)
        and all(
            response_registers[name]
            == {"op": "call_response", "call_index": 0, "register": name, "width": 32}
            for name in _REGISTERS
        )
        and set(response_flags) == set(_FLAGS)
        and all(
            response_flags[name] == {"op": "call_flag", "call_index": 0, "flag": name}
            for name in _FLAGS
        )
    )


def _category(unit: Mapping[str, Any]) -> str:
    events = unit.get("semantics", {}).get("external_events", [])
    if any(event.get("kind") == "external_call" for event in events):
        return "external_call"
    if any(event.get("kind") == "internal_call" for event in events):
        return "internal_call"
    if unit.get("control", {}).get("has_indirect_target"):
        return "indirect_control"
    if unit.get("control", {}).get("kind") == "branch":
        return "branch"
    return str(unit.get("control", {}).get("kind") or "straight_line")


def _direct_targets(unit: Mapping[str, Any]) -> tuple[int, ...]:
    return tuple(
        int(value) for value in unit.get("control", {}).get("direct_targets", [])
        if isinstance(value, int)
    )


def _cluster_control_contract(
    units: Sequence[Mapping[str, Any]],
    by_rva: Mapping[int, Mapping[str, Any]],
    recovered_by_source: Mapping[str, Mapping[str, Any]],
) -> list[dict[str, Any]]:
    member_rvas = {int(_source_span(unit)["rva_start"]) for unit in units}
    rows: list[dict[str, Any]] = []
    for unit in units:
        source_id = str(unit["id"])
        outcome = unit.get("semantics", {}).get("outcome", {})
        kind = str(outcome.get("kind") or unit.get("control", {}).get("kind"))
        if kind in {"indirect_jump", "indirect_call"}:
            recovery = recovered_by_source.get(source_id)
            targets = [] if recovery is None else list(recovery.get("target_rvas", []))
            rows.append(
                {
                    "kind": kind,
                    "source_unit_id": source_id,
                    "target_rvas": sorted(int(value) for value in targets),
                    "target_unit_ids": sorted(
                        str(by_rva[int(value)]["id"])
                        for value in targets if int(value) in by_rva
                    ),
                    "finite_target_inventory": recovery is not None,
                    "dispatch_entries": (
                        [] if recovery is None else copy.deepcopy(recovery.get("entries", []))
                    ),
                    "selector": (
                        None if recovery is None else copy.deepcopy(recovery.get("index"))
                    ),
                    "table": (
                        None if recovery is None else copy.deepcopy(recovery.get("table"))
                    ),
                }
            )
            continue
        targets = [
            target for target in _direct_targets(unit) if target not in member_rvas
        ]
        if targets or kind in {"return", "terminate", "external_jump"}:
            rows.append(
                {
                    "kind": kind,
                    "source_unit_id": source_id,
                    "target_rvas": sorted(targets),
                    "target_unit_ids": sorted(
                        str(by_rva[target]["id"])
                        for target in targets if target in by_rva
                    ),
                }
            )
    deduplicated = {
        json.dumps(row, sort_keys=True, separators=(",", ":")): row for row in rows
    }
    return [deduplicated[key] for key in sorted(deduplicated)]


def _validation_requirements(
    units: Sequence[Mapping[str, Any]],
    contract_analysis: Mapping[str, Any],
    recovered_by_source: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    indirect_entries = sum(
        len(recovered_by_source[str(unit["id"])].get("entries", []))
        for unit in units if str(unit["id"]) in recovered_by_source
    )
    return {
        "generation": "lazy_per_workspace",
        "families": [
            "boundary_values",
            "branch_witnesses",
            "finite_dispatch_exhaustion",
            "valid_and_faulting_memory",
            "exact_and_partial_aliasing",
            "typed_source_mutations",
        ],
        "straight_line_solver_claim": {
            "available": not any(
                unit.get("semantics", {}).get(field)
                for unit in units
                for field in ("memory_events", "external_events")
            ),
            "scope": "normalized output and control expressions only",
            "arbitrary_c_source_proved": False,
        },
        "memory_views": len(contract_analysis.get("memory_views", [])),
        "atomic_effects": len(contract_analysis.get("atomic_effects", [])),
        "external_services": len(contract_analysis.get("external_services", [])),
        "callbacks": len(contract_analysis.get("callbacks", [])),
        "finite_dispatch_cases": indirect_entries,
    }


def _semantic_expressions(units: Sequence[Mapping[str, Any]]) -> list[Any]:
    result: list[Any] = []
    for unit in units:
        semantics = unit.get("semantics", {})
        for field in ("register_writes", "flag_writes", "memory_events", "external_events", "outcome", "stack_delta"):
            result.append(semantics.get(field))
    return result


def _value_inputs(values: Sequence[Any]) -> list[dict[str, str]]:
    found: set[tuple[str, str]] = set()
    def visit(value: Any) -> None:
        if isinstance(value, dict):
            if value.get("op") == "reg" and isinstance(value.get("name"), str):
                found.add(("register", value["name"]))
            elif value.get("op") == "flag" and isinstance(value.get("name"), str):
                found.add(("flag", value["name"]))
            for item in value.values():
                visit(item)
        elif isinstance(value, list):
            for item in value:
                visit(item)
    visit(list(values))
    return [{"kind": kind, "name": name} for kind, name in sorted(found)]


def _value_outputs(units: Sequence[Mapping[str, Any]]) -> list[dict[str, str]]:
    found = set()
    for unit in units:
        semantics = unit.get("semantics", {})
        found.update(("register", str(item["register"])) for item in semantics.get("register_writes", []))
        found.update(("flag", str(item["flag"])) for item in semantics.get("flag_writes", []))
    return [{"kind": kind, "name": name} for kind, name in sorted(found)]


def _memory_inventory(units: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    result = []
    seen = set()
    for unit in units:
        for event in unit.get("semantics", {}).get("memory_events", []):
            semantic_expression = copy.deepcopy(event.get("address"))
            expression = _display_expr(semantic_expression)
            key = (
                _canonical_json(semantic_expression),
                int(event.get("width", 0)),
                str(event.get("kind")),
            )
            if key in seen:
                continue
            seen.add(key)
            result.append(
                {
                    "address_expression": expression,
                    "semantic_expression": semantic_expression,
                    "width": int(event.get("width", 0)),
                    "access": {"read": "read", "write": "write"}.get(str(event.get("kind")), "read_write"),
                }
            )
    return sorted(result, key=lambda item: (item["address_expression"], item["access"], item["width"]))


def _event_inventory(units: Sequence[Mapping[str, Any]], *, include_internal: bool) -> list[dict[str, Any]]:
    result = []
    for unit in units:
        for event in unit.get("semantics", {}).get("external_events", []):
            kind = str(event.get("kind"))
            if kind == "internal_call" and not include_internal:
                continue
            if kind == "external_call":
                identity = f"{str(event.get('dll')).lower()}!{event.get('symbol') or '#' + str(event.get('ordinal'))}"
            else:
                identity = f"internal:rva:{int(event.get('target_rva', 0)):08x}"
            result.append({"kind": kind, "identity": identity})
    return result


def _work_score(*, template: str | None, unit_count: int, memory_count: int, event_count: int, predecessor_count: int, blockers: int) -> int:
    return (
        (0 if template else 1000) + blockers * 500 + unit_count * 20
        + memory_count * 10 + event_count * 30 + min(predecessor_count, 20)
    )


def _source_span(unit: Mapping[str, Any]) -> Mapping[str, Any]:
    return _object(_object(unit.get("source"), "unit source").get("original"), "unit original span")


def _display_expr(value: Any) -> str:
    if isinstance(value, dict):
        op = value.get("op")
        if op in {"reg", "flag"}:
            return f"input.{value.get('name')}"
        if op == "const":
            return f"0x{int(value.get('value', 0)):08x}"
        if op == "add32":
            args = value.get("args", [])
            return " + ".join(_display_expr(item) for item in args)
        return json.dumps(value, sort_keys=True, separators=(",", ":"))
    return str(value)


def _reg_expr(name: str) -> dict[str, Any]:
    return {"op": "reg", "name": name, "width": 32}


def _stack_address_expr(offset: int) -> dict[str, Any]:
    if offset == 0:
        return _reg_expr("esp")
    return {
        "op": "add32",
        "args": [_reg_expr("esp"), {"op": "const", "value": offset, "width": 32}],
    }


def _read_object(path: Path, context: str) -> dict[str, Any]:
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise StageAInputError(f"cannot read {context} {path}: {exc}") from exc
    return _object(payload, context)


def _object(value: Any, context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise StageAInputError(f"{context} must be an object")
    return value


def _array(value: Any, context: str) -> list[Any]:
    if not isinstance(value, list):
        raise StageAInputError(f"{context} must be an array")
    return value


def _require_format(payload: Mapping[str, Any], expected: str, context: str) -> None:
    if payload.get("format") != expected:
        raise StageAInputError(f"{context} must use format {expected}")


def _canonical_sha256(value: Any) -> str:
    return sha256(_canonical_json(value).encode("ascii")).hexdigest()


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )


__all__ = ["write_reconstruction_plan"]

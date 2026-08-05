"""Editable typed-C workspaces derived from the sanitized machine IR.

The machine interpreter remains the candidate-only behavioral baseline.  This
module turns its normalized units into small, content-bound work items with a
portable implementation layer and a generated x86 adapter.  It never opens or
executes the original binary.
"""

from __future__ import annotations

import copy
import json
import re
import shutil
import subprocess
import tempfile
from difflib import SequenceMatcher
from collections import Counter
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from .artifact_formats import (
    RECONSTRUCTION_PLAN_FORMAT,
    RECONSTRUCTION_REGISTRY_FORMAT,
    RECONSTRUCTION_STATUS_FORMAT,
    RECONSTRUCTION_VALIDATION_CASES_FORMAT,
    COMPONENT_BACKEND_WORKSPACE_FORMAT,
)
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
from .reconstruction_validation import synthesize_reconstruction_validation
from .region_replacement import (
    REGION_REPLACEMENT_BUNDLE_FORMAT,
    RegionReplacementManifest,
    generate_region_override_table,
    load_region_replacement_manifest,
    validate_region_replacement,
    write_region_replacement_manifest,
)
from .stage_binary import StageAInputError
from .util import sha256_file, write_json


_REGISTERS = ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
_FLAGS = ("cf", "zf", "sf", "of", "pf", "df")
_SUPPORTED_TEMPLATES = frozenset(
    {"compare_branch", "constant_external_call", "store_then_zero_call"}
)
_EDITABLE_TEMPLATES = _SUPPORTED_TEMPLATES | {"manual_contract"}
_REGIONAL_KERNEL_FORMAT = "stage-b-regional-interpreter-kernel-v1"
_REGIONAL_KERNEL_FLAGS = ("-std=c11", "-O0", "-g0", "-fno-pie")


@dataclass(frozen=True)
class MachineIRInput:
    root: Path
    manifest_path: Path
    machine_ir_path: Path
    manifest: Mapping[str, Any]
    units: tuple[Mapping[str, Any], ...]
    machine_ir_sha256: str


@dataclass(frozen=True)
class ReconstructionWorkspace:
    root: Path
    workspace: Path
    contract: Path
    source: Path
    portable_source: Path
    portable_header: Path
    manifest: Path
    cases: Path


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


def create_component_backend_workspace(
    *,
    plan: Path | None,
    machine_ir: Path | None,
    interpreter_package: Path,
    out_dir: Path,
    cluster_id: str | None = None,
    entry_rva: int | None = None,
    adapter_unit_ids: Sequence[str] | None = None,
    prepared_slice: Mapping[str, Any] | None = None,
) -> ReconstructionWorkspace:
    """Create a content-bound editable workspace for one planned cluster."""

    if (cluster_id is None) == (entry_rva is None):
        raise StageAInputError("select exactly one of cluster_id or entry_rva")
    if prepared_slice is None:
        if plan is None or machine_ir is None:
            raise StageAInputError(
                "reconstruction workspace requires plan and machine IR inputs"
            )
        plan_path = Path(plan)
        plan_payload = _read_object(plan_path, "reconstruction plan")
        _require_format(plan_payload, RECONSTRUCTION_PLAN_FORMAT, "reconstruction plan")
        package = _load_machine_ir(machine_ir)
        if plan_payload.get("inputs", {}).get("machine_ir", {}).get("sha256") != package.machine_ir_sha256:
            raise StageAInputError("reconstruction plan is stale for the selected machine IR")
    else:
        if plan is not None or machine_ir is not None:
            raise StageAInputError(
                "prepared reconstruction slices cannot be combined with full inputs"
            )
        prepared = _object(prepared_slice, "prepared reconstruction slice")
        plan_sha256 = prepared.get("plan_sha256")
        machine_ir_sha256 = prepared.get("machine_ir_sha256")
        units = prepared.get("units")
        cluster = prepared.get("cluster")
        if not isinstance(plan_sha256, str) or not plan_sha256:
            raise StageAInputError("prepared reconstruction slice omits plan binding")
        if not isinstance(machine_ir_sha256, str) or not machine_ir_sha256:
            raise StageAInputError("prepared reconstruction slice omits machine IR binding")
        if not isinstance(units, list) or not units:
            raise StageAInputError("prepared reconstruction slice has no machine units")
        if not isinstance(cluster, Mapping):
            raise StageAInputError("prepared reconstruction slice has no cluster")
        unit_ids = [str(item.get("id")) for item in units if isinstance(item, Mapping)]
        if len(unit_ids) != len(units) or len(set(unit_ids)) != len(unit_ids):
            raise StageAInputError(
                "prepared reconstruction slice machine-unit inventory is invalid"
            )
        plan_payload = {
            "format": RECONSTRUCTION_PLAN_FORMAT,
            "plan_sha256": plan_sha256,
            "inputs": {"machine_ir": {"sha256": machine_ir_sha256}},
            "clusters": [cluster],
        }
        package = MachineIRInput(
            root=Path("."),
            manifest_path=Path("machine-ir-manifest.json"),
            machine_ir_path=Path("machine-ir.jsonl"),
            manifest={},
            units=tuple(units),
            machine_ir_sha256=machine_ir_sha256,
        )
    matches = [
        item
        for item in _array(plan_payload.get("clusters"), "reconstruction plan clusters")
        if (cluster_id is not None and item.get("id") == cluster_id)
        or (entry_rva is not None and item.get("entry_rva") == entry_rva)
    ]
    if len(matches) != 1:
        selector = cluster_id if cluster_id is not None else f"0x{entry_rva:08x}"
        raise StageAInputError(f"reconstruction plan has {len(matches)} matches for {selector}")
    cluster = _object(matches[0], "selected reconstruction cluster")
    template = cluster.get("template") or "manual_contract"
    if template not in _EDITABLE_TEMPLATES:
        raise StageAInputError(f"cluster {cluster['id']} has an unknown source template")
    cluster = {**cluster, "template": template}

    interpreter_root, interpreter = _load_interpreter_package(interpreter_package)
    program = _object(interpreter.get("program"), "interpreter program")
    program_path = interpreter_root / str(program.get("path"))
    if not program_path.is_file() or sha256_file(program_path) != program.get("sha256"):
        raise StageAInputError("interpreter baseline program binding is stale")

    by_id = {str(unit["id"]): unit for unit in package.units}
    units = [by_id[str(unit_id)] for unit_id in cluster["unit_ids"]]
    adapter_units = units
    if adapter_unit_ids is not None:
        requested = [str(unit_id) for unit_id in adapter_unit_ids]
        missing = sorted(set(requested) - set(by_id))
        if missing:
            raise StageAInputError(
                f"component adapter references unknown machine units: {missing}"
            )
        if not set(cluster["unit_ids"]).issubset(requested):
            raise StageAInputError(
                "component adapter unit inventory omits reconstruction cluster members"
            )
        adapter_units = [by_id[unit_id] for unit_id in requested]
    entry = by_id[str(cluster["entry_unit_id"])]
    composition = cluster.get("composition", {})
    if (
        len(units) > 1
        and isinstance(composition, Mapping)
        and composition.get("status") == "complete"
        and not isinstance(composition.get("summary_unit"), Mapping)
    ):
        planned_composition = copy.deepcopy(dict(composition))
        composition = compose_linear_reconstruction_cluster(
            units, entry_unit_id=str(cluster["entry_unit_id"])
        )
        cluster = {
            **cluster,
            "composition_plan": planned_composition,
            "composition": composition,
        }
    if len(units) > 1 and (
        not isinstance(composition, Mapping)
        or composition.get("status") != "complete"
        or not isinstance(composition.get("summary_unit"), Mapping)
    ):
        component_boundary = cluster.get("component_execution_boundary", {})
        if (
            not isinstance(component_boundary, Mapping)
            or component_boundary.get("status") != "checked"
            or composition.get("status") != "checked_by_component_interface"
        ):
            raise StageAInputError(
                f"cluster {cluster['id']} has no complete multi-unit semantic composition"
            )
        semantic_units = units
    else:
        semantic_units = (
            [composition["summary_unit"]] if len(units) > 1 else units
        )
    out_dir = Path(out_dir)
    if out_dir.exists() and any(out_dir.iterdir()):
        raise StageAInputError(f"reconstruction workspace is not empty: {out_dir}")
    source_dir = out_dir / "src"
    contract_dir = out_dir / "contract"
    tests_dir = out_dir / "tests"
    source_dir.mkdir(parents=True, exist_ok=True)
    contract_dir.mkdir(parents=True, exist_ok=True)
    tests_dir.mkdir(parents=True, exist_ok=True)

    symbol = f"replace_region_{int(cluster['entry_rva']):08x}"
    header_text, portable_text, adapter_text = _render_source(
        template=str(template),
        cluster=cluster,
        entry=entry,
        units=adapter_units,
        symbol=symbol,
    )
    source_path = source_dir / "replacement.c"
    source_path.write_text(adapter_text, encoding="ascii")
    portable_source_path = source_dir / "implementation.c"
    portable_source_path.write_text(portable_text, encoding="ascii")
    portable_header_path = source_dir / "implementation.h"
    portable_header_path.write_text(header_text, encoding="ascii")
    generated_source_path = contract_dir / "generated-implementation.c"
    generated_source_path.write_text(portable_text, encoding="ascii")
    contract_path = contract_dir / "cluster-contract.json"
    write_json(contract_path, cluster)
    cases_payload = _generate_cases(
        cluster=cluster, entry=entry, units=semantic_units
    )
    cases_path = tests_dir / "cases.json"
    write_json(cases_path, cases_payload)
    validation_payload = _synthesize_cluster_validation(cluster, semantic_units)
    validation_payload["mutations"] = _mutation_inventory(adapter_units)
    validation_payload["counts"]["mutations"] = len(
        validation_payload["mutations"]
    )
    validation_cases_path = tests_dir / "generated-validation-cases.json"
    write_json(validation_cases_path, validation_payload)

    evidence_id = "evidence:candidate-only-regional-check"
    manifest_payload = _replacement_manifest_payload(
        cluster=cluster,
        entry=entry,
        units=units,
        source_path=source_path,
        source_root=out_dir,
        symbol=symbol,
        machine_ir_sha256=package.machine_ir_sha256,
        baseline_program_sha256=str(program["sha256"]),
        evidence_id=evidence_id,
    )
    manifest_path = out_dir / "region-replacement.json"
    manifest = write_region_replacement_manifest(
        manifest_path, manifest_payload, source_root=out_dir
    )
    workspace_payload = {
        "format": COMPONENT_BACKEND_WORKSPACE_FORMAT,
        "status": "editable",
        "executes_original_binary": False,
        "cluster_id": cluster["id"],
        "cluster_contract_sha256": cluster["contract_sha256"],
        "template": template,
        "bindings": {
            "plan_sha256": plan_payload.get("plan_sha256"),
            "machine_ir_sha256": package.machine_ir_sha256,
            "interpreter_package_sha256": sha256_file(
                interpreter_root / "state-machine-interpreter-package.json"
            ),
            "baseline_program_sha256": program["sha256"],
            "replacement_manifest_sha256": manifest.manifest_sha256,
        },
        "files": {
            "portable_source": "src/implementation.c",
            "portable_header": "src/implementation.h",
            "machine_adapter_source": "src/replacement.c",
            "cluster_contract": "contract/cluster-contract.json",
            "generated_source_reference": "contract/generated-implementation.c",
            "cases": "tests/cases.json",
            "generated_validation_cases": "tests/generated-validation-cases.json",
            "replacement_manifest": "region-replacement.json",
        },
        "source_boundaries": {
            "portable_logic": {
                "path": "src/implementation.c",
                "line_start": 1,
                "line_end": len(portable_text.splitlines()),
            },
            "generated_machine_adapter": {
                "path": "src/replacement.c",
                "line_start": 1,
                "line_end": len(adapter_text.splitlines()),
            },
        },
        "portability": {
            "portable_logic_uses_machine_state": False,
            "generated_adapter_uses_machine_state": True,
            "service_dependencies": [
                item["identity"] for item in cluster.get("external_events", [])
            ],
            "remaining_manual_work": (
                "rename inferred values and replace the generated portable helper with "
                "domain-level types without changing its boundary contract"
            ),
        },
    }
    workspace_payload["workspace_sha256"] = _canonical_sha256(workspace_payload)
    workspace_path = out_dir / "workspace.json"
    write_json(workspace_path, workspace_payload)
    (out_dir / "README.md").write_text(
        _workspace_readme(
            cluster,
            workspace_payload["source_boundaries"]["portable_logic"],
            workspace_payload["source_boundaries"]["generated_machine_adapter"],
        ),
        encoding="ascii",
    )
    return ReconstructionWorkspace(
        root=out_dir,
        workspace=workspace_path,
        contract=contract_path,
        source=source_path,
        portable_source=portable_source_path,
        portable_header=portable_header_path,
        manifest=manifest_path,
        cases=cases_path,
    )


def rebind_component_backend_workspace(*, workspace: Path) -> RegionReplacementManifest:
    """Refresh the source hash after an intentional portable-source edit."""

    root = Path(workspace)
    metadata = _load_workspace(root)
    manifest_path = root / str(metadata["files"]["replacement_manifest"])
    payload = _read_object(manifest_path, "region replacement manifest")
    source_path = root / str(payload["source"]["path"])
    portable_path = root / str(metadata["source_boundaries"]["portable_logic"]["path"])
    generated_path = root / str(metadata["files"]["generated_source_reference"])
    edit_map = _source_edit_map(generated_path, portable_path)
    write_json(root / "edit-map.json", edit_map)
    payload["source"]["sha256"] = sha256_file(source_path)
    payload["source"]["line_end"] = len(
        source_path.read_text(encoding="ascii").splitlines()
    )
    for support in payload.get("support_sources", []):
        support["sha256"] = sha256_file(root / str(support["path"]))
    manifest = write_region_replacement_manifest(
        manifest_path, payload, source_root=root
    )
    metadata["bindings"]["replacement_manifest_sha256"] = manifest.manifest_sha256
    metadata["source_boundaries"]["portable_logic"]["line_end"] = len(
        portable_path.read_text(encoding="ascii").splitlines()
    )
    metadata.pop("workspace_sha256", None)
    metadata["workspace_sha256"] = _canonical_sha256(metadata)
    write_json(root / "workspace.json", metadata)
    return manifest


def check_component_backend_workspace(
    *,
    workspace: Path,
    baseline_observations: Path,
    replacement_observations: Path,
    out: Path | None = None,
) -> dict[str, Any]:
    """Run the fail-closed candidate-only validator for an editable workspace."""

    root = Path(workspace)
    metadata = _load_workspace(root)
    report_path = Path(out) if out is not None else root / "validation-report.json"
    report = validate_region_replacement(
        manifest=root / str(metadata["files"]["replacement_manifest"]),
        baseline_observations=Path(baseline_observations),
        replacement_observations=Path(replacement_observations),
        source_root=root,
        out=report_path,
    )
    edit_map_path = root / "edit-map.json"
    if edit_map_path.is_file() and report["deltas"]:
        edit_map = _read_object(edit_map_path, "workspace edit map")
        for delta in report["deltas"]:
            delta["repair_locations"] = edit_map["changed_ranges"]
        write_json(report_path, report)
    return report


def _workspace_fallback_on_unimplemented(root: Path) -> bool:
    component_metadata_path = root / "component-workspace.json"
    if not component_metadata_path.is_file():
        return False
    component_metadata = _read_object(
        component_metadata_path, "component workspace"
    )
    domain = _object(
        component_metadata.get("activation", {}).get("domain", {"kind": "total"}),
        "component activation domain",
    )
    if domain.get("kind") == "total":
        return False
    if domain.get("kind") != "guarded_partial":
        raise StageAInputError(
            f"unsupported component activation domain: {domain.get('kind')}"
        )
    if (
        domain.get("fallback") != "canonical_machine_ir"
        or domain.get("decline_before_guest_writes") is not True
        or domain.get("decline_before_observable_effects") is not True
    ):
        raise StageAInputError(
            "guarded component has an unsafe interpreter fallback contract"
        )
    return True


def run_component_backend_check(
    *,
    workspace: Path,
    interpreter_package: Path,
    out_dir: Path,
    compiler: str = "cc",
    regional_kernel: Path | None = None,
) -> dict[str, Any]:
    """Execute generated baseline and replacement cases, then validate them.

    This is a candidate-only differential check.  It compiles the sanitized
    interpreter package and editable replacement; no original PE path is
    accepted by the interface.
    """

    root = Path(workspace)
    metadata = _load_workspace(root)
    fallback_on_unimplemented = _workspace_fallback_on_unimplemented(root)
    interpreter_root, interpreter = _load_interpreter_package(interpreter_package)
    manifest = load_region_replacement_manifest(
        root / str(metadata["files"]["replacement_manifest"]), source_root=root
    )
    cases = _read_object(root / str(metadata["files"]["cases"]), "reconstruction cases")
    if cases.get("format") != "stage-b-reconstruction-cases-v1":
        raise StageAInputError("unsupported reconstruction cases format")
    if cases.get("cluster_id") != manifest.cluster["id"]:
        raise StageAInputError("reconstruction cases are stale for the replacement cluster")
    source = root / str(manifest.source["path"])
    support_sources = [
        root / str(item["path"])
        for item in manifest.support_sources
        if str(item["path"]).endswith(".c")
    ]
    if shutil.which(compiler) is None:
        raise StageAInputError(f"regional check compiler is unavailable: {compiler}")
    required = [
        interpreter_root / "state-machine-interpreter.c",
        interpreter_root / "state-machine-program.c",
        interpreter_root / "state-machine-runtime.h",
        interpreter_root / "state-machine-interpreter.h",
    ]
    missing = [str(path) for path in required if not path.is_file()]
    if missing:
        raise StageAInputError(f"interpreter package omits regional check files: {missing}")
    kernel_objects: list[Path] | None = None
    kernel_binding: dict[str, Any] | None = None
    if regional_kernel is not None:
        kernel_objects, kernel_binding = _load_regional_kernel(
            Path(regional_kernel),
            interpreter_root=interpreter_root,
            interpreter=interpreter,
            compiler=compiler,
        )

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="spaghetti-region-check-") as temporary:
        build = Path(temporary)
        harness_path = build / "regional-harness.c"
        harness_path.write_text(
            _render_regional_harness(
                manifest,
                cases,
                fallback_on_unimplemented=fallback_on_unimplemented,
                typed_x87_runtime=(
                    "STAGE_B_MACHINE_STATE_HAS_X87"
                    in (interpreter_root / "state-machine-runtime.h").read_text(
                        encoding="ascii"
                    )
                ),
            ),
            encoding="ascii",
        )
        executable = build / "regional-harness"
        command = [
            compiler,
            *_REGIONAL_KERNEL_FLAGS,
            "-no-pie",
            "-I",
            str(interpreter_root),
            str(harness_path),
            str(source),
            *(str(path) for path in support_sources),
            *(
                (str(path) for path in kernel_objects)
                if kernel_objects is not None
                else (
                    str(interpreter_root / "state-machine-interpreter.c"),
                    str(interpreter_root / "state-machine-program.c"),
                )
            ),
            "-o",
            str(executable),
        ]
        built = subprocess.run(command, check=False, capture_output=True, text=True)
        if built.returncode != 0:
            raise StageAInputError(
                "regional replacement did not compile:\n" + built.stderr.strip()
            )
        executed = subprocess.run(
            [str(executable)], check=False, capture_output=True, text=True
        )
        if executed.returncode != 0:
            raise StageAInputError(
                f"regional candidate harness exited {executed.returncode}: "
                f"{executed.stderr.strip()}"
            )
    baseline, replacement = _parse_regional_observations(
        manifest=manifest, cases=cases, text=executed.stdout
    )
    baseline_path = out_dir / "baseline-observations.json"
    replacement_path = out_dir / "replacement-observations.json"
    write_json(baseline_path, baseline)
    write_json(replacement_path, replacement)
    report = check_component_backend_workspace(
        workspace=root,
        baseline_observations=baseline_path,
        replacement_observations=replacement_path,
        out=out_dir / "validation-report.json",
    )
    evidence = {
        "format": "stage-b-reconstruction-regional-check-v1",
        "status": report["status"],
        "executes_original_binary": False,
        "candidate_only": True,
        "bindings": {
            "replacement_manifest_sha256": manifest.manifest_sha256,
            "interpreter_package_sha256": sha256_file(
                interpreter_root / "state-machine-interpreter-package.json"
            ),
            "baseline_program_sha256": interpreter["program"]["sha256"],
            "cases_sha256": cases["cases_sha256"],
            "regional_kernel": kernel_binding,
        },
        "counts": {
            "cases": len(cases["cases"]),
            "compared_cases": report["counts"]["compared_cases"],
            "deltas": report["counts"]["deltas"],
        },
    }
    write_json(out_dir / "regional-check-evidence.json", evidence)
    return report


def build_reconstruction_regional_kernel(
    *, interpreter_package: Path, out_dir: Path, compiler: str = "cc"
) -> dict[str, Any]:
    """Compile the immutable host-side interpreter units for regional checks."""

    interpreter_root, interpreter = _load_interpreter_package(interpreter_package)
    if shutil.which(compiler) is None:
        raise StageAInputError(f"regional kernel compiler is unavailable: {compiler}")
    sources = (
        interpreter_root / "state-machine-interpreter.c",
        interpreter_root / "state-machine-program.c",
    )
    missing = [str(path) for path in sources if not path.is_file()]
    if missing:
        raise StageAInputError(f"interpreter package omits regional kernel files: {missing}")
    output = Path(out_dir)
    objects_dir = output / "objects"
    objects_dir.mkdir(parents=True, exist_ok=True)
    object_rows: list[dict[str, Any]] = []
    for index, source in enumerate(sources):
        object_path = objects_dir / f"{index:02d}-{source.stem}.o"
        command = [
            compiler,
            *_REGIONAL_KERNEL_FLAGS,
            "-I",
            str(interpreter_root),
            "-c",
            str(source),
            "-o",
            str(object_path),
        ]
        built = subprocess.run(command, check=False, capture_output=True, text=True)
        if built.returncode != 0 or not object_path.is_file():
            raise StageAInputError(
                "regional interpreter kernel did not compile:\n" + built.stderr.strip()
            )
        object_rows.append(
            {
                "source": source.name,
                "source_sha256": sha256_file(source),
                "object": object_path.relative_to(output).as_posix(),
                "object_sha256": sha256_file(object_path),
            }
        )
    core = {
        "format": _REGIONAL_KERNEL_FORMAT,
        "status": "checked",
        "executes_original_binary": False,
        "bindings": {
            "interpreter_package_sha256": sha256_file(
                interpreter_root / "state-machine-interpreter-package.json"
            ),
            "baseline_program_sha256": interpreter["program"]["sha256"],
            "compiler": _regional_compiler_identity(compiler),
            "flags": list(_REGIONAL_KERNEL_FLAGS),
        },
        "objects": object_rows,
    }
    payload = {**core, "kernel_sha256": _canonical_sha256(core)}
    write_json(output / "regional-kernel.json", payload)
    return payload


def _load_regional_kernel(
    root: Path,
    *,
    interpreter_root: Path,
    interpreter: Mapping[str, Any],
    compiler: str,
) -> tuple[list[Path], dict[str, Any]]:
    manifest_path = root / "regional-kernel.json" if root.is_dir() else root
    package_root = manifest_path.parent
    payload = _read_object(manifest_path, "regional interpreter kernel")
    _require_format(payload, _REGIONAL_KERNEL_FORMAT, "regional interpreter kernel")
    expected = payload.get("kernel_sha256")
    core = copy.deepcopy(payload)
    core.pop("kernel_sha256", None)
    if expected != _canonical_sha256(core):
        raise StageAInputError("regional interpreter kernel self-hash is stale")
    expected_bindings = {
        "interpreter_package_sha256": sha256_file(
            interpreter_root / "state-machine-interpreter-package.json"
        ),
        "baseline_program_sha256": interpreter["program"]["sha256"],
        "compiler": _regional_compiler_identity(compiler),
        "flags": list(_REGIONAL_KERNEL_FLAGS),
    }
    if payload.get("bindings") != expected_bindings:
        raise StageAInputError("regional interpreter kernel bindings are stale")
    expected_sources = {
        "state-machine-interpreter.c": interpreter_root / "state-machine-interpreter.c",
        "state-machine-program.c": interpreter_root / "state-machine-program.c",
    }
    objects: list[Path] = []
    rows = payload.get("objects")
    if not isinstance(rows, list) or len(rows) != len(expected_sources):
        raise StageAInputError("regional interpreter kernel object inventory is incomplete")
    for row in rows:
        if not isinstance(row, Mapping) or row.get("source") not in expected_sources:
            raise StageAInputError("regional interpreter kernel has an unknown object source")
        source = expected_sources[str(row["source"])]
        object_path = package_root / str(row.get("object"))
        if row.get("source_sha256") != sha256_file(source):
            raise StageAInputError("regional interpreter kernel source binding is stale")
        if not object_path.is_file() or row.get("object_sha256") != sha256_file(object_path):
            raise StageAInputError("regional interpreter kernel object binding is stale")
        objects.append(object_path)
    return objects, {
        "kernel_sha256": expected,
        "manifest_sha256": sha256_file(manifest_path),
    }


def _regional_compiler_identity(compiler: str) -> dict[str, str]:
    executable = shutil.which(compiler)
    if executable is None:
        raise StageAInputError(f"regional kernel compiler is unavailable: {compiler}")
    completed = subprocess.run(
        [executable, "--version"], check=False, capture_output=True, text=True
    )
    if completed.returncode != 0:
        raise StageAInputError("regional kernel compiler version query failed")
    return {
        "path": str(Path(executable).resolve()),
        "version": completed.stdout.splitlines()[0].strip(),
    }


def promote_component_backend_workspaces(
    *,
    workspaces: Sequence[Path],
    out_dir: Path,
    fallback_on_unimplemented_workspaces: Sequence[Path] = (),
) -> dict[str, Any]:
    """Validate and combine checked workspaces into one override package."""

    if not workspaces:
        raise StageAInputError("promotion requires at least one reconstruction workspace")
    roots = [Path(item).resolve() for item in workspaces]
    fallback_roots = {
        Path(item).resolve() for item in fallback_on_unimplemented_workspaces
    }
    unknown_fallbacks = fallback_roots.difference(roots)
    if unknown_fallbacks:
        raise StageAInputError(
            "fallback workspaces are not present in the promotion inventory: "
            + ", ".join(str(item) for item in sorted(unknown_fallbacks))
        )
    manifests = []
    for root in roots:
        metadata = _load_workspace(root)
        manifest = load_region_replacement_manifest(
            root / str(metadata["files"]["replacement_manifest"]), source_root=root
        )
        report_path = root / "validation-report.json"
        if not report_path.is_file():
            raise StageAInputError(f"workspace has no validation report: {root}")
        report = _read_object(report_path, "regional validation report")
        if report.get("status") != "qualified":
            raise StageAInputError(f"workspace is not qualified: {root}")
        if (
            report.get("bindings", {}).get("replacement_manifest_sha256")
            != manifest.manifest_sha256
        ):
            raise StageAInputError(f"workspace validation is stale: {root}")
        manifests.append((root, manifest))

    promoted_portable_source_hashes = {
        str(support["sha256"])
        for _, manifest in manifests
        for support in manifest.support_sources
        if support.get("role") == "portable_source"
    }

    out_dir = Path(out_dir)
    source_root = out_dir / "sources"
    source_root.mkdir(parents=True, exist_ok=True)
    copied_manifests = []
    entries = []
    for root, manifest in sorted(manifests, key=lambda item: item[1].id):
        destination = source_root / _slug(manifest.id)
        destination.mkdir(parents=True, exist_ok=True)
        source = root / str(manifest.source["path"])
        copied_source = destination / source.name
        shutil.copyfile(source, copied_source)
        payload = manifest.to_payload()
        payload["source"]["path"] = copied_source.relative_to(out_dir).as_posix()
        payload["source"]["sha256"] = sha256_file(copied_source)
        copied_support = []
        dependency_directories_to_omit = {
            Path(str(support["path"])).parent
            for support in manifest.support_sources
            if support.get("role") == "adapter_support"
            and "component-dependencies" in Path(str(support["path"])).parts
            and str(support["sha256"]) in promoted_portable_source_hashes
        }
        for support in manifest.support_sources:
            support_source = root / str(support["path"])
            support_relative = Path(str(support["path"]))
            if support_relative.parent in dependency_directories_to_omit:
                continue
            if support_relative.parts and support_relative.parts[0] == "src":
                support_relative = Path(*support_relative.parts[1:])
            else:
                support_relative = Path("support") / support_relative
            support_destination = destination / support_relative
            support_destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(support_source, support_destination)
            copied_support.append(
                {
                    **support,
                    "path": support_destination.relative_to(out_dir).as_posix(),
                    "sha256": sha256_file(support_destination),
                }
            )
        if payload["format"] == REGION_REPLACEMENT_BUNDLE_FORMAT:
            payload["support_sources"] = copied_support
        copied_manifest_path = destination / "region-replacement.json"
        copied = write_region_replacement_manifest(
            copied_manifest_path, payload, source_root=out_dir
        )
        copied_manifests.append(copied)
        entries.append(
            {
                "id": copied.id,
                "cluster_id": copied.cluster["id"],
                "entry_rva": copied.cluster["entry_rva"],
                "manifest": copied_manifest_path.relative_to(out_dir).as_posix(),
                "manifest_sha256": copied.manifest_sha256,
                "fallback_on_unimplemented": root in fallback_roots,
            }
        )
    override = generate_region_override_table(
        manifests=copied_manifests,
        source_root=out_dir,
        out_dir=out_dir,
        fallback_on_unimplemented_ids=[
            manifest.id
            for root, manifest in manifests
            if root in fallback_roots
        ],
    )
    registry = {
        "format": RECONSTRUCTION_REGISTRY_FORMAT,
        "status": "qualified",
        "executes_original_binary": False,
        "entries": entries,
        "override_table": {
            "path": override.manifest.name,
            "sha256": sha256_file(override.manifest),
        },
        "counts": {"replacements": len(entries)},
    }
    registry["registry_sha256"] = _canonical_sha256(registry)
    write_json(out_dir / "reconstruction-registry.json", registry)
    return registry


def write_reconstruction_status(
    *, plan: Path, registry: Path | None, out: Path
) -> dict[str, Any]:
    """Report source-lifting progress without conflating it with proof status."""

    plan_payload = _read_object(Path(plan), "reconstruction plan")
    _require_format(plan_payload, RECONSTRUCTION_PLAN_FORMAT, "reconstruction plan")
    entries: list[Mapping[str, Any]] = []
    registry_sha256 = None
    if registry is not None:
        registry_path = Path(registry)
        registry_payload = _read_object(registry_path, "reconstruction registry")
        _require_format(
            registry_payload, RECONSTRUCTION_REGISTRY_FORMAT, "reconstruction registry"
        )
        entries = [
            _object(item, "reconstruction registry entry")
            for item in _array(registry_payload.get("entries"), "registry entries")
        ]
        registry_sha256 = sha256_file(registry_path)
    replaced = {str(item["cluster_id"]): item for item in entries}
    clusters = _array(plan_payload.get("clusters"), "reconstruction plan clusters")
    reachable = [item for item in clusters if bool(item.get("reachable"))]
    portable = [item for item in reachable if bool(item.get("portable_source_ready"))]
    promoted = [item for item in reachable if str(item.get("id")) in replaced]
    next_work = [
        {
            "cluster_id": item["id"],
            "entry_rva": item["entry_rva"],
            "category": item["category"],
            "template": item.get("template"),
            "work_score": item["work_score"],
            "blockers": item["blockers"],
        }
        for item in reachable
        if str(item["id"]) not in replaced
    ][:25]
    payload = {
        "format": RECONSTRUCTION_STATUS_FORMAT,
        "status": "qualified" if len(promoted) == len(reachable) else "incomplete",
        "executes_original_binary": False,
        "bindings": {
            "plan_sha256": plan_payload.get("plan_sha256"),
            "registry_sha256": registry_sha256,
        },
        "counts": {
            "reachable_clusters": len(reachable),
            "portable_source_ready": len(portable),
            "promoted_clusters": len(promoted),
            "remaining_clusters": len(reachable) - len(promoted),
            "remaining_without_template": sum(
                not bool(item.get("portable_source_ready"))
                for item in reachable
                if str(item.get("id")) not in replaced
            ),
        },
        "coverage": {
            "promoted_cluster_ids": sorted(str(item["id"]) for item in promoted),
            "next_work": next_work,
        },
        "interpretation": (
            "This reports source-lifting progress only. Qualification of a region is "
            "candidate-only behavioral evidence and does not qualify the whole program."
        ),
    }
    write_json(Path(out), payload)
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


def _load_interpreter_package(value: Path) -> tuple[Path, Mapping[str, Any]]:
    value = Path(value)
    if value.is_dir():
        root = value
        path = root / "state-machine-interpreter-package.json"
    else:
        root = value.parent
        path = value
    payload = _read_object(path, "interpreter package")
    if payload.get("format") != "stage-b-semantic-interpreter-package-v1":
        raise StageAInputError("unsupported interpreter package format")
    return root, payload


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


def _render_source(
    *,
    template: str,
    cluster: Mapping[str, Any],
    entry: Mapping[str, Any],
    units: Sequence[Mapping[str, Any]],
    symbol: str,
) -> tuple[str, str, str]:
    if template == "compare_branch":
        return _render_compare_branch(entry, symbol)
    if template == "constant_external_call":
        return _render_external_call(entry, symbol)
    if template == "store_then_zero_call":
        return _render_store_zero(entry, units, symbol)
    if template == "manual_contract":
        return _render_manual_contract(cluster, symbol)
    raise StageAInputError(f"unsupported reconstruction template {template}")


def _source_files(
    header: Sequence[str], portable: Sequence[str], adapter: Sequence[str]
) -> tuple[str, str, str]:
    header_lines = [
        "#ifndef SPAGHETTI_RECONSTRUCTED_IMPLEMENTATION_H",
        "#define SPAGHETTI_RECONSTRUCTED_IMPLEMENTATION_H",
        "",
        "#include <stdbool.h>",
        "#include <stdint.h>",
        "",
        *header,
        "",
        "#endif",
    ]
    portable_lines = ['#include "implementation.h"', "", *portable]
    adapter_lines = [
        '#include "state-machine-runtime.h"',
        '#include "implementation.h"',
        "",
        *adapter,
    ]
    return tuple("\n".join(lines) + "\n" for lines in (
        header_lines, portable_lines, adapter_lines
    ))


def _eflags_sync_lines(indent: str = "") -> list[str]:
    """Synchronize the packed EFLAGS view after writing modeled flag fields."""

    return [
        "#ifdef STAGE_B_MACHINE_STATE_HAS_EFLAGS",
        f"{indent}state->eflags =",
        f"{indent}    (state->eflags & ~UINT32_C(0x00000cd5)) |",
        f"{indent}    ((state->cf & 1U) << 0) | ((state->pf & 1U) << 2) |",
        f"{indent}    ((state->zf & 1U) << 6) | ((state->sf & 1U) << 7) |",
        f"{indent}    ((state->df & 1U) << 10) | ((state->of & 1U) << 11);",
        "#endif",
    ]


def _render_compare_branch(unit: Mapping[str, Any], symbol: str) -> tuple[str, str, str]:
    operands = unit["instructions"][0]["operands"]
    left = str(operands[0]["name"])
    right = str(operands[1]["name"])
    outcome = unit["semantics"]["outcome"]
    entry_rva = int(_source_span(unit)["rva_start"])
    header = [
        "typedef struct reconstructed_compare_result {",
        "  uint32_t difference;",
        "  bool equal;",
        "} reconstructed_compare_result;",
        "",
        "reconstructed_compare_result compare_values(uint32_t left, uint32_t right);",
    ]
    portable = [
        "reconstructed_compare_result compare_values(uint32_t left, uint32_t right) {",
        "  reconstructed_compare_result result = { left - right, left == right };",
        "  return result;",
        "}",
    ]
    adapter = [
        "static uint32_t even_parity_low_byte(uint32_t value) {",
        "  value ^= value >> 4;",
        "  value &= 0x0fU;",
        "  return (UINT32_C(0x9669) >> value) & 1U;",
        "}",
        "",
        f"stage_b_step_result {symbol}(stage_b_runtime *rt, stage_b_machine_state *state) {{",
        f"  const uint32_t left = state->{left};",
        f"  const uint32_t right = state->{right};",
        "  reconstructed_compare_result result;",
        "  (void)rt;",
        f"  state->original_rva = UINT32_C(0x{entry_rva:08x});",
        "  result = compare_values(left, right);",
        "  state->cf = left < right;",
        "  state->of = ((left ^ right) & (left ^ result.difference) & UINT32_C(0x80000000)) != 0U;",
        "  state->pf = even_parity_low_byte(result.difference);",
        "  state->sf = (result.difference >> 31) & 1U;",
        "  state->zf = result.equal;",
        *_eflags_sync_lines("  "),
        "  return (stage_b_step_result){",
        "      STAGE_B_BRANCH,",
        f"      result.equal ? UINT32_C(0x{int(outcome['true_target_rva']):08x}) : UINT32_C(0x{int(outcome['false_target_rva']):08x}),",
        "      0U",
        "  };",
        "}",
    ]
    return _source_files(header, portable, adapter)


def _render_manual_contract(
    cluster: Mapping[str, Any], symbol: str
) -> tuple[str, str, str]:
    input_fields = [
        (str(item["kind"]), str(item["name"]))
        for item in cluster.get("inputs", [])
        if item.get("kind") in {"register", "flag"}
    ]
    output_fields = [
        (str(item["kind"]), str(item["name"]))
        for item in cluster.get("outputs", [])
        if item.get("kind") in {"register", "flag"}
    ]
    memory_fields = _manual_memory_fields(cluster)
    atomic_fields = _manual_atomic_fields(cluster)
    declared_atomic_effects = cluster.get("typed_contract", {}).get(
        "atomic_effects", []
    )
    if len(atomic_fields) != len(declared_atomic_effects):
        raise StageAInputError(
            "manual contract cannot lower every declared atomic effect"
        )
    memory_inputs = [field for field in memory_fields if field["read"]]
    memory_outputs = [field for field in memory_fields if field["write"]]
    header = [
        "typedef enum reconstructed_control_kind {",
        "  RECONSTRUCTED_FALLTHROUGH = 0,",
        "  RECONSTRUCTED_JUMP = 1,",
        "  RECONSTRUCTED_BRANCH = 2,",
        "  RECONSTRUCTED_RETURN = 3,",
        "  RECONSTRUCTED_INDIRECT_JUMP = 4",
        "} reconstructed_control_kind;",
        "",
        "typedef struct reconstructed_region_inputs {",
    ]
    header.extend(
        f"  uint32_t {kind}_{_slug(name).replace('-', '_')};"
        for kind, name in input_fields
    )
    if not input_fields:
        header.append("  uint32_t unused;")
    header.extend(
        f"  uint32_t {field['name']};" for field in memory_inputs
    )
    for field in atomic_fields:
        header.append(f"  uint32_t {field['observed_name']};")
        header.append(f"  uint32_t {field['exchanged_name']};")
    header.extend(["} reconstructed_region_inputs;", "", "typedef struct reconstructed_region_outputs {"])
    header.extend(
        f"  uint32_t {kind}_{_slug(name).replace('-', '_')};"
        for kind, name in output_fields
    )
    for field in memory_outputs:
        header.append(f"  uint32_t {field['name']};")
        header.append(f"  bool write_{field['name']};")
    header.extend(
        [
            "  uint32_t control_kind;",
            "  uint32_t target_rva;",
            "  uint32_t value;",
            "} reconstructed_region_outputs;",
            "",
            "bool reconstruct_region(const reconstructed_region_inputs *inputs,",
            "                        reconstructed_region_outputs *outputs);",
        ]
    )
    portable = [
        "bool reconstruct_region(const reconstructed_region_inputs *inputs,",
        "                        reconstructed_region_outputs *outputs) {",
        "  (void)inputs;",
        "  (void)outputs;",
        "  /* Implement the typed cluster contract in contract/cluster-contract.json. */",
        "  return false;",
        "}",
    ]
    adapter = [
        f"stage_b_step_result {symbol}(stage_b_runtime *rt, stage_b_machine_state *state) {{",
        "  reconstructed_region_inputs inputs = {",
    ]
    adapter.extend(
        f"    .{kind}_{_slug(name).replace('-', '_')} = state->{name},"
        for kind, name in input_fields
    )
    if not input_fields:
        adapter.append("    .unused = 0U,")
    adapter.extend(
        [
            "  };",
            "  reconstructed_region_outputs outputs = { 0U };",
            f"  state->original_rva = UINT32_C(0x{int(cluster['entry_rva']):08x});",
        ]
    )
    if memory_inputs or memory_outputs or atomic_fields:
        adapter.insert(-1, "  uint32_t memory_fault = 0U;")
        requirements = ["rt == 0"]
        if memory_inputs:
            requirements.append("rt->read == 0")
        if memory_outputs:
            requirements.append("rt->write == 0")
        adapter.extend(
            [
                f"  if ({' || '.join(requirements)})",
                "    return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, state->original_rva, 0U };",
            ]
        )
    else:
        adapter.append("  (void)rt;")
    for field in atomic_fields:
        adapter.extend(
            [
                "  stage_b_runtime_atomic_compare_exchange(",
                f"      rt, {field['address_c']}, {field['width']}U,",
                f"      {field['expected_c']}, {field['desired_c']},",
                f"      &inputs.{field['observed_name']},",
                f"      &inputs.{field['exchanged_name']}, &memory_fault);",
                "  if (memory_fault)",
                "    return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, state->original_rva, 0U };",
            ]
        )
    for field in memory_inputs:
        adapter.extend(
            [
                f"  inputs.{field['name']} = rt->read(rt->context, {field['address_c']}, {field['width']}U, &memory_fault);",
                "  if (memory_fault)",
                "    return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, state->original_rva, 0U };",
            ]
        )
    adapter.extend(
        [
            "  if (!reconstruct_region(&inputs, &outputs))",
            "    return (stage_b_step_result){ STAGE_B_UNIMPLEMENTED, state->original_rva, 0U };",
        ]
    )
    for field in memory_outputs:
        adapter.extend(
            [
                f"  if (outputs.write_{field['name']}) {{",
                f"    rt->write(rt->context, {field['address_c']}, {field['width']}U, outputs.{field['name']}, &memory_fault);",
                "    if (memory_fault)",
                "      return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, state->original_rva, 0U };",
                "  }",
            ]
        )
    adapter.extend(
        f"  state->{name} = outputs.{kind}_{_slug(name).replace('-', '_')};"
        for kind, name in output_fields
    )
    if any(kind == "flag" for kind, _name in output_fields):
        adapter.extend(_eflags_sync_lines("  "))
    adapter.extend(
        [
            "  return (stage_b_step_result){",
            "    (stage_b_control_kind)outputs.control_kind, outputs.target_rva, outputs.value",
            "  };",
            "}",
        ]
    )
    return _source_files(header, portable, adapter)


def _manual_memory_fields(cluster: Mapping[str, Any]) -> list[dict[str, Any]]:
    contract = cluster.get("typed_contract", {})
    if not isinstance(contract, Mapping):
        return []
    atomic_addresses = {
        json.dumps(
            effect.get("target", {}).get("address"),
            sort_keys=True,
            separators=(",", ":"),
        )
        for effect in contract.get("atomic_effects", [])
        if isinstance(effect, Mapping)
        and isinstance(effect.get("target"), Mapping)
        and isinstance(effect["target"].get("address"), Mapping)
    }
    result = []
    for view_index, view in enumerate(contract.get("memory_views", [])):
        if not isinstance(view, Mapping) or not isinstance(view.get("base"), Mapping):
            continue
        for field in view.get("fields", []):
            if not isinstance(field, Mapping):
                continue
            width = field.get("width_bytes")
            offset = field.get("offset")
            if (
                not isinstance(width, int)
                or isinstance(width, bool)
                or width not in {1, 2, 4}
                or not isinstance(offset, int)
                or isinstance(offset, bool)
            ):
                continue
            observations = field.get("observations", [])
            if any(
                isinstance(observation, Mapping)
                and json.dumps(
                    observation.get("address"),
                    sort_keys=True,
                    separators=(",", ":"),
                )
                in atomic_addresses
                for observation in observations
            ):
                continue
            address = copy.deepcopy(view["base"])
            if offset:
                address = {
                    "op": "add32",
                    "args": [
                        address,
                        {"op": "const", "value": offset & 0xFFFFFFFF, "width": 32},
                    ],
                }
            address_c = _manual_semantic_expression_c(address)
            if address_c is None:
                continue
            accesses = set(str(item) for item in field.get("accesses", []))
            suffix = f"p{offset}" if offset >= 0 else f"m{-offset}"
            result.append(
                {
                    "name": f"memory_view_{view_index:02d}_{suffix}",
                    "address_c": address_c,
                    "width": width,
                    "read": bool(accesses & {"read", "read_write"}),
                    "write": bool(accesses & {"write", "read_write"}),
                }
            )
    return result


def _manual_atomic_fields(cluster: Mapping[str, Any]) -> list[dict[str, Any]]:
    contract = cluster.get("typed_contract", {})
    if not isinstance(contract, Mapping):
        return []
    summary = cluster.get("composition", {}).get("summary_unit", {})
    semantics = summary.get("semantics", {}) if isinstance(summary, Mapping) else {}
    writes = [
        event
        for event in semantics.get("memory_events", [])
        if isinstance(event, Mapping) and event.get("kind") == "write"
    ]
    result = []
    for index, effect in enumerate(contract.get("atomic_effects", [])):
        if not isinstance(effect, Mapping) or effect.get("operation") != "compare_exchange":
            continue
        target = effect.get("target")
        if not isinstance(target, Mapping):
            continue
        address = target.get("address")
        width = target.get("width_bytes")
        address_c = _manual_semantic_expression_c(address)
        if address_c is None or width not in {1, 2, 4}:
            continue
        write = next(
            (
                event
                for event in writes
                if event.get("address") == address and event.get("width") == width
            ),
            None,
        )
        expressions = _compare_exchange_expressions(
            None if write is None else write.get("value"), address, int(width)
        )
        if expressions is None:
            continue
        expected, desired = expressions
        expected_c = _manual_semantic_expression_c(expected)
        desired_c = _manual_semantic_expression_c(desired)
        if expected_c is None or desired_c is None:
            continue
        result.append(
            {
                "observed_name": f"atomic_{index:02d}_observed",
                "exchanged_name": f"atomic_{index:02d}_exchanged",
                "address_c": address_c,
                "width": int(width),
                "expected_c": expected_c,
                "desired_c": desired_c,
                "address_expression": copy.deepcopy(address),
                "expected_expression": copy.deepcopy(expected),
                "desired_expression": copy.deepcopy(desired),
            }
        )
    return result


def _compare_exchange_expressions(
    value: Any, address: Any, width: int
) -> tuple[Mapping[str, Any], Mapping[str, Any]] | None:
    if not isinstance(value, Mapping) or value.get("op") != "ite":
        return None
    args = value.get("args")
    if not isinstance(args, list) or len(args) != 3:
        return None
    condition, desired, unchanged = args
    load = {"op": "load", "address": address, "width": width}
    if unchanged != load or not isinstance(condition, Mapping) or condition.get("op") != "eq":
        return None
    compare_args = condition.get("args")
    if not isinstance(compare_args, list) or len(compare_args) != 2:
        return None
    if compare_args[0] == load and isinstance(compare_args[1], Mapping):
        expected = compare_args[1]
    elif compare_args[1] == load and isinstance(compare_args[0], Mapping):
        expected = compare_args[0]
    else:
        return None
    return copy.deepcopy(expected), copy.deepcopy(desired)


def _manual_semantic_expression_c(value: Any) -> str | None:
    if not isinstance(value, Mapping):
        return None
    op = value.get("op")
    if op == "reg" and str(value.get("name")) in _REGISTERS:
        return f"state->{value['name']}"
    if op == "const" and isinstance(value.get("value"), int):
        return f"UINT32_C(0x{int(value['value']) & 0xFFFFFFFF:08x})"
    binary = {
        "add": "+", "add32": "+", "sub": "-", "sub32": "-",
        "mul": "*", "mul32": "*", "and": "&", "and32": "&",
        "or": "|", "or32": "|", "xor": "^", "xor32": "^",
    }.get(str(op))
    args = value.get("args")
    if binary is not None and isinstance(args, list) and len(args) == 2:
        left = _manual_semantic_expression_c(args[0])
        right = _manual_semantic_expression_c(args[1])
        if left is not None and right is not None:
            return f"({left} {binary} {right})"
    return None


def _render_external_call(unit: Mapping[str, Any], symbol: str) -> tuple[str, str, str]:
    event = unit["semantics"]["external_events"][0]
    bound_event = _bound_external_instruction_event(unit)
    if bound_event is None:
        raise StageAInputError(
            "external-call template requires one ordered event bound to its call instruction"
        )
    stack_input = event["stack_inputs"][0]
    argument = int(stack_input["value"]["value"])
    dll = str(event["dll"])
    imported = str(event.get("symbol") or "")
    return_rva = int(event["return_rva"])
    entry_rva = int(_source_span(unit)["rva_start"])
    instruction_rva = int(bound_event["instruction_rva"])
    method = _slug(imported or f"ordinal_{event.get('ordinal')}").replace("-", "_")
    header = [
        "typedef struct reconstructed_services {",
        "  void *context;",
        f"  int (*{method})(void *context, uint32_t argument);",
        "} reconstructed_services;",
        "",
        "int run_service_operation(reconstructed_services *services);",
    ]
    portable = [
        "int run_service_operation(reconstructed_services *services) {",
        f"  return services->{method}(services->context, UINT32_C({argument}));",
        "}",
    ]
    adapter = [
        "typedef struct machine_service_context {",
        "  stage_b_runtime *runtime;",
        "  stage_b_machine_state *state;",
        "  stage_b_call_status status;",
        "} machine_service_context;",
        "",
        f"static int invoke_{method}(void *opaque, uint32_t argument) {{",
        "  machine_service_context *context = (machine_service_context *)opaque;",
        "  stage_b_machine_state output = *context->state;",
        "  const uint32_t arguments[] = { argument };",
        "  const stage_b_stack_input stack_inputs[] = { { 0U, 4U, argument } };",
        "  const stage_b_call_event event = {",
        "    STAGE_B_CALL_EXTERNAL_IMPORT,",
        f"    UINT32_C(0x{instruction_rva:08x}), 0U, 0U, UINT32_C(0x{return_rva:08x}),",
        f"    \"{_c_escape(dll)}\", \"{_c_escape(imported)}\", {int(event.get('ordinal') or 0)}U, {1 if event.get('ordinal') is not None else 0}U,",
        "    arguments, 1U, stack_inputs, 1U",
        "  };",
        "  context->status = stage_b_invoke_call(",
        "      context->runtime, &event, context->state, &output);",
        "  if (context->status == STAGE_B_CALL_OK)",
        "    *context->state = output;",
        "  return context->status == STAGE_B_CALL_OK ? 0 : -1;",
        "}",
        "",
        f"stage_b_step_result {symbol}(stage_b_runtime *rt, stage_b_machine_state *state) {{",
        "  uint32_t memory_fault = 0U;",
        "  machine_service_context context = { rt, state, STAGE_B_CALL_UNIMPLEMENTED };",
        f"  reconstructed_services services = {{ &context, invoke_{method} }};",
        f"  state->original_rva = UINT32_C(0x{entry_rva:08x});",
        "  if (rt == 0 || rt->write == 0)",
        "    return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, 0U, 0U };",
        f"  rt->write(rt->context, state->esp + {int(stack_input['offset'])}U, 4U, UINT32_C({argument}), &memory_fault);",
        "  if (memory_fault)",
        "    return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, 0U, 0U };",
        "  if (run_service_operation(&services) != 0) {",
        "    stage_b_control_kind kind = context.status == STAGE_B_CALL_MEMORY_FAULT",
        "        ? STAGE_B_MEMORY_FAULT : STAGE_B_EXTERNAL_FAULT;",
        "    return (stage_b_step_result){ kind, state->original_rva, 0U };",
        "  }",
        f"  return (stage_b_step_result){{ STAGE_B_FALLTHROUGH, UINT32_C(0x{return_rva:08x}), 0U }};",
        "}",
    ]
    return _source_files(header, portable, adapter)


def _render_store_zero(
    entry: Mapping[str, Any], units: Sequence[Mapping[str, Any]], symbol: str
) -> tuple[str, str, str]:
    semantics = entry["semantics"]
    reads = [item for item in semantics["memory_events"] if item["kind"] == "read"]
    writes = [item for item in semantics["memory_events"] if item["kind"] == "write"]
    if len(reads) != 1 or len(writes) != 1:
        raise StageAInputError("store/zero template requires one read and one write")
    source_address = _const_expr(reads[0]["address"], "static read address")
    destination = writes[0]["address"]
    if destination.get("op") != "reg":
        raise StageAInputError("store/zero template requires a register destination")
    destination_reg = str(destination["name"])
    return_rva = int(semantics["outcome"]["target_rva"])
    call = next(
        (
            event
            for event in semantics.get("external_events", [])
            if event.get("kind") == "internal_call"
        ),
        None,
    )
    if not isinstance(call, Mapping):
        raise StageAInputError("store/zero template requires one internal call")
    call_target_rva = int(call["target_rva"])
    call_return_rva = int(call["return_rva"])
    if call_return_rva != return_rva:
        raise StageAInputError("store/zero internal return does not match fallthrough")
    helper = next(
        (
            unit
            for unit in units
            if int(_source_span(unit)["rva_start"]) == call_target_rva
        ),
        None,
    )
    owns_helper = helper is not None
    entry_rva = int(_source_span(entry)["rva_start"])
    header = [
        "typedef struct reconstructed_initialization {",
        "  uint32_t stored_value;",
        "  uint32_t result;",
        "} reconstructed_initialization;",
        "",
        "reconstructed_initialization initialize_word(uint32_t shared_value);",
    ]
    portable = [
        "reconstructed_initialization initialize_word(uint32_t shared_value) {",
        "  reconstructed_initialization result = { shared_value, 0U };",
        "  return result;",
        "}",
    ]
    adapter = [
        f"stage_b_step_result {symbol}(stage_b_runtime *rt, stage_b_machine_state *state) {{",
        "  uint32_t memory_fault = 0U;",
        "  uint32_t shared_value;",
        "  uint32_t return_target;",
        "  uint32_t caller_esp;",
        "  reconstructed_initialization result;",
        f"  state->original_rva = UINT32_C(0x{entry_rva:08x});",
        "  if (rt == 0 || rt->read == 0 || rt->write == 0)",
        "    return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, 0U, 0U };",
        f"  shared_value = rt->read(rt->context, UINT32_C(0x{source_address:08x}), 4U, &memory_fault);",
        "  if (memory_fault)",
        "    return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, 0U, 0U };",
        "  result = initialize_word(shared_value);",
        f"  rt->write(rt->context, state->{destination_reg}, 4U, result.stored_value, &memory_fault);",
        "  if (memory_fault)",
        "    return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, 0U, 0U };",
        "  state->edx = shared_value;",
    ]
    if owns_helper:
        adapter.extend(
            [
                "  caller_esp = state->esp;",
                "  state->esp = caller_esp - UINT32_C(4);",
                f"  rt->write(rt->context, state->esp, 4U, UINT32_C(0x{call_return_rva:08x}), &memory_fault);",
                "  if (memory_fault)",
                f"    return (stage_b_step_result){{ STAGE_B_MEMORY_FAULT, UINT32_C(0x{int(call['return_rva']) - 5:08x}), 0U }};",
                "  state->eax = result.result;",
                "  state->cf = 0U;",
                "  state->of = 0U;",
                "  state->pf = 1U;",
                "  state->sf = 0U;",
                "  state->zf = 1U;",
                *_eflags_sync_lines("  "),
                "  return_target = rt->read(rt->context, state->esp, 4U, &memory_fault);",
                "  if (memory_fault)",
                f"    return (stage_b_step_result){{ STAGE_B_MEMORY_FAULT, UINT32_C(0x{call_target_rva + 2:08x}), 0U }};",
                "  state->esp = caller_esp;",
                f"  if (return_target != UINT32_C(0x{call_return_rva:08x}))",
                f"    return (stage_b_step_result){{ STAGE_B_UNIMPLEMENTED, UINT32_C(0x{call_target_rva + 2:08x}), return_target }};",
            ]
        )
    else:
        adapter.extend(
            [
                "  (void)return_target;",
                "  (void)caller_esp;",
                "  state->eax = result.result;",
                "  state->cf = 0U;",
                "  state->of = 0U;",
                "  state->pf = 1U;",
                "  state->sf = 0U;",
                "  state->zf = 1U;",
                *_eflags_sync_lines("  "),
            ]
        )
    adapter.extend(
        [
            f"  return (stage_b_step_result){{ STAGE_B_FALLTHROUGH, UINT32_C(0x{return_rva:08x}), 0U }};",
            "}",
        ]
    )
    return _source_files(header, portable, adapter)


def _checked_machine_abi_comparison(
    event: Mapping[str, Any],
) -> dict[str, Any] | None:
    value = event.get("abi_contract")
    if value is None:
        return None
    contract = _object(value, "external-event ABI contract")
    binding_value = contract.get("profile_binding")
    if not isinstance(binding_value, Mapping):
        return None
    binding = _object(binding_value, "external-event ABI profile binding")
    contract_id = contract.get("contract_id")
    template = contract.get("template")
    profile_id = binding.get("profile_id")
    profile_sha256 = binding.get("profile_sha256")
    if (
        not isinstance(contract_id, int)
        or isinstance(contract_id, bool)
        or not 0 <= contract_id <= 0xFFFFFFFF
        or not isinstance(template, str)
        or not template
        or not isinstance(profile_id, str)
        or not profile_id
        or not isinstance(profile_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", profile_sha256) is None
    ):
        return None
    return {
        "mode": "checked_machine_abi_v1",
        "abi_contract_sha256": _canonical_sha256(contract),
        "template": template,
        "profile_id": profile_id,
        "profile_sha256": profile_sha256,
        "contract_id": contract_id,
    }


def _replacement_manifest_payload(
    *, cluster: Mapping[str, Any], entry: Mapping[str, Any],
    units: Sequence[Mapping[str, Any]], source_path: Path, source_root: Path,
    symbol: str, machine_ir_sha256: str, baseline_program_sha256: str,
    evidence_id: str,
    ) -> dict[str, Any]:
    live_inputs = [_live_value(item, evidence_id) for item in cluster["inputs"]]
    output_names = sorted(set(_REGISTERS + _FLAGS))
    live_outputs = [
        _live_value({"kind": "flag" if name in _FLAGS else "register", "name": name}, evidence_id)
        for name in output_names
    ]
    memory_views = []
    for index, item in enumerate(cluster.get("memory", [])):
        memory_views.append(
            {
                "id": f"memory:view-{index:02d}",
                "base_expression": _canonical_json(item["semantic_expression"]),
                "byte_length": int(item["width"]),
                "length_expression": None,
                "access": item["access"],
                "representation": "little-endian machine bytes",
                "evidence_ids": [evidence_id],
            }
        )
    controls = []
    for index, item in enumerate(cluster["control"]):
        controls.append(
            {
                "id": f"exit:{index:02d}-{item['kind']}",
                "kind": item["kind"],
                "target_unit_ids": item["target_unit_ids"],
                "target_rvas": item["target_rvas"],
                "target_values": sorted(
                    {
                        int(entry["target_address"])
                        for entry in item.get("dispatch_entries", [])
                        if isinstance(entry, Mapping)
                        and isinstance(entry.get("target_address"), int)
                    }
                ),
                "evidence_ids": [evidence_id],
            }
        )
    events = []
    for unit in sorted(units, key=lambda item: int(_source_span(item)["rva_start"])):
        semantics = _object(unit.get("semantics", {}), "unit semantics")
        unit_events = _array(
            semantics.get("external_events", []), "unit external events"
        )
        ordered_events = [
            _object(item, "ordered external event")
            for item in _array(
                semantics.get("ordered_events", []), "unit ordered events"
            )
            if isinstance(item, Mapping) and item.get("family") == "external"
        ]
        if ordered_events and len(unit_events) != len(ordered_events):
            raise StageAInputError(
                f"unit {unit['id']} external-event order is incomplete"
            )
        ordered_for_events: Sequence[Mapping[str, Any] | None] = (
            ordered_events if ordered_events else [None] * len(unit_events)
        )
        for event, ordered in zip(unit_events, ordered_for_events, strict=True):
            event = _object(event, "unit external event")
            event_kind = str(event.get("kind"))
            if event_kind == "external_call":
                identity = f"{event.get('dll') or ''}!{event.get('symbol') or ''}"
                manifest_kind = "import_call"
            elif event_kind == "indirect_call":
                identity = "indirect-call"
                manifest_kind = "indirect_call"
            elif event_kind == "internal_call":
                continue
            else:
                raise StageAInputError(
                    f"unit {unit['id']} has unsupported event kind {event_kind}"
                )
            site = {
                "id": f"event-site:{len(events):02d}",
                "kind": manifest_kind,
                "identity": identity,
                "evidence_ids": [evidence_id],
            }
            if ordered is not None:
                site["instruction_rva"] = int(ordered["instruction_rva"])
                site["return_rva"] = int(event["return_rva"])
            comparison = _checked_machine_abi_comparison(event)
            if comparison is not None:
                site["comparison"] = comparison
            events.append(site)
    cluster_events = _array(cluster.get("external_events", []), "cluster external events")
    if len(events) != len(cluster_events):
        raise StageAInputError("cluster external-event inventory disagrees with its units")
    for event, cluster_event in zip(events, cluster_events, strict=True):
        event["identity"] = str(
            _object(cluster_event, "cluster external event")["identity"]
        )
    composition = cluster.get("composition", {})
    summary = (
        composition.get("summary_unit", {})
        if isinstance(composition, Mapping)
        else {}
    )
    summary_semantics = (
        summary.get("semantics", {}) if isinstance(summary, Mapping) else {}
    )
    stack_delta = summary_semantics.get(
        "stack_delta", entry.get("semantics", {}).get("stack_delta", {})
    )
    net_bytes = stack_delta.get("net_bytes")
    if not isinstance(net_bytes, int):
        net_bytes = 0
    evidence_sha = _canonical_sha256(
        {
            "cluster_contract_sha256": cluster["contract_sha256"],
            "unit_contracts": sorted(str(item["source"]["contract_sha256"]) for item in units),
            "template": cluster["template"],
        }
    )
    return {
        "format": REGION_REPLACEMENT_BUNDLE_FORMAT,
        "id": f"replacement:{int(cluster['entry_rva']):08x}",
        "bindings": {
            "machine_ir_sha256": machine_ir_sha256,
            "baseline_program_sha256": baseline_program_sha256,
            "cluster_contract_sha256": cluster["contract_sha256"],
        },
        "cluster": {
            "id": cluster["id"],
            "entry_unit_id": cluster["entry_unit_id"],
            "entry_rva": cluster["entry_rva"],
            "unit_ids": cluster["unit_ids"],
            "rva_spans": cluster["rva_spans"],
        },
        "source": {
            "path": source_path.relative_to(source_root).as_posix(),
            "sha256": sha256_file(source_path),
            "symbol": symbol,
            "line_start": 1,
            "line_end": len(source_path.read_text(encoding="ascii").splitlines()),
        },
        "support_sources": [
            {
                "path": "src/implementation.c",
                "sha256": sha256_file(source_root / "src/implementation.c"),
                "role": "portable_source",
            },
            {
                "path": "src/implementation.h",
                "sha256": sha256_file(source_root / "src/implementation.h"),
                "role": "portable_header",
            },
        ],
        "abi": {
            "calling_convention": "machine_state",
            "stack_delta": net_bytes,
            "parameters": [],
            "results": [],
            "preserved_registers": [],
            "clobbered_registers": output_names,
            "evidence_ids": [evidence_id],
        },
        "type_hypotheses": [],
        "live_state": {"inputs": live_inputs, "outputs": live_outputs},
        "memory_views": memory_views,
        "expectations": {
            "control": controls,
            "fault": {
                "allow_none": True,
                "variants": [
                    {"id": "fault:memory", "kind": "memory_fault", "evidence_ids": [evidence_id]},
                    {"id": "fault:external", "kind": "external_fault", "evidence_ids": [evidence_id]},
                ],
            },
            "external_events": events,
        },
        "evidence": [
            {
                "id": evidence_id,
                "class": "differential",
                "status": "qualified",
                "artifact_sha256": evidence_sha,
                "detail": (
                    "the generated baseline and editable replacement must be checked "
                    "on the same candidate-only regional cases before promotion"
                ),
            }
        ],
    }


def _generate_cases(
    *, cluster: Mapping[str, Any], entry: Mapping[str, Any], units: Sequence[Mapping[str, Any]]
) -> dict[str, Any]:
    template = cluster["template"]
    registers = {
        "eax": 0x70002000, "ebx": 0x11223344, "ecx": 0x55667788,
        "edx": 0x99AABBCC, "esi": 0x12345678, "edi": 0x87654321,
        "ebp": 0x70003000, "esp": 0x70001000,
    }
    flags = {name: index & 1 for index, name in enumerate(_FLAGS)}
    cases = []
    if template == "compare_branch":
        operands = entry["instructions"][0]["operands"]
        left, right = str(operands[0]["name"]), str(operands[1]["name"])
        for name, a, b in (
            ("equal", 7, 7), ("unsigned-less", 1, 2),
            ("unsigned-greater", 2, 1), ("signed-overflow", 0x80000000, 1),
        ):
            values = dict(registers)
            values[left], values[right] = a, b
            cases.append(_case(name, values, flags, []))
    elif template == "constant_external_call":
        stack_input = entry["semantics"]["external_events"][0]["stack_inputs"][0]
        for index in range(2):
            values = {name: (value + index * 0x11111111) & 0xFFFFFFFF for name, value in registers.items()}
            values["esp"] = 0x70001000 + index * 0x100
            cases.append(
                _case(
                    f"service-{index}", values, flags,
                    [{"address": values["esp"] + int(stack_input["offset"]), "bytes": "a5a5a5a5"}],
                )
            )
    elif template == "store_then_zero_call":
        read = next(item for item in entry["semantics"]["memory_events"] if item["kind"] == "read")
        static_address = _const_expr(read["address"], "static read address")
        for index, value in enumerate((0x01020304, 0xDEADBEEF)):
            values = dict(registers)
            values["eax"] = 0x70002000 + index * 0x100
            values["esp"] = 0x70001000 + index * 0x100
            cases.append(
                _case(
                    f"initialize-{index}", values, flags,
                    [
                        {"address": static_address, "bytes": value.to_bytes(4, "little").hex()},
                        {"address": values["eax"], "bytes": "a5a5a5a5"},
                        {"address": values["esp"] - 4, "bytes": "cccccccc"},
                    ],
                )
            )
    else:
        generated = _synthesize_cluster_validation(cluster, units)
        boundary_cases = (
            []
            if generated["indirect_dispatch_cases"]
            else generated["boundary_cases"]
        )
        for index, generated_case in enumerate(boundary_cases):
            values = dict(registers)
            case_flags = dict(flags)
            for name, value in generated_case.get("inputs", {}).items():
                if name in values:
                    values[name] = int(value) & 0xFFFFFFFF
                elif name in case_flags:
                    case_flags[name] = int(value) & 1
            cases.append(
                _case(
                    f"generated-{index:04d}",
                    values,
                    case_flags,
                    _initial_memory_for_contract(
                        cluster.get("typed_contract", {}), values
                    ),
                )
            )
        for index, generated_case in enumerate(
            generated["indirect_dispatch_cases"]
        ):
            binding = generated_case.get("dispatch_binding", {})
            if not isinstance(binding, Mapping) or binding.get("executable") is not True:
                continue
            values = dict(registers)
            case_flags = dict(flags)
            for name, value in generated_case.get("inputs", {}).items():
                if name in values:
                    values[name] = int(value) & 0xFFFFFFFF
                elif name in case_flags:
                    case_flags[name] = int(value) & 1
            memory = _initial_memory_for_contract(
                cluster.get("typed_contract", {}), values
            )
            metadata = generated_case.get("metadata", {})
            if (
                isinstance(metadata, Mapping)
                and isinstance(metadata.get("table_entry_address"), int)
                and isinstance(metadata.get("target_address"), int)
            ):
                memory = _add_initial_memory_word(
                    memory,
                    int(metadata["table_entry_address"]),
                    int(metadata["target_address"]),
                )
            cases.append(
                _case(
                    f"dispatch-{index:04d}", values, case_flags, memory
                )
            )
        cases.extend(
            _executable_alias_cases(
                generated=generated,
                contract=cluster.get("typed_contract", {}),
                registers=registers,
                flags=flags,
            )
        )
        cases.extend(
            _atomic_validation_cases(
                cluster=cluster, registers=registers, flags=flags
            )
        )
        if not cases:
            cases.append(
                _case(
                    "generated-default",
                    registers,
                    flags,
                    _initial_memory_for_contract(
                        cluster.get("typed_contract", {}), registers
                    ),
                )
            )
    payload = {
        "format": "stage-b-reconstruction-cases-v1",
        "cluster_id": cluster["id"],
        "entry_unit_id": cluster["entry_unit_id"],
        "entry_rva": cluster["entry_rva"],
        "cases": cases,
    }
    payload["cases_sha256"] = _canonical_sha256(payload)
    return payload


def _executable_alias_cases(
    *,
    generated: Mapping[str, Any],
    contract: Mapping[str, Any],
    registers: Mapping[str, int],
    flags: Mapping[str, int],
) -> list[dict[str, Any]]:
    views = {
        str(item["id"]): item
        for item in _validation_memory_views(contract)
        if isinstance(item.get("id"), str)
    }
    result = []
    seen: set[tuple[tuple[str, int], ...]] = set()
    for index, raw in enumerate(generated.get("memory_cases", [])):
        if not isinstance(raw, Mapping) or raw.get("scenario") not in {
            "alias_exact", "alias_partial",
        }:
            continue
        placements = raw.get("placements")
        if not isinstance(placements, list) or len(placements) != 1:
            continue
        placement = placements[0]
        if not isinstance(placement, Mapping):
            continue
        left = views.get(str(placement.get("left_view_id")))
        right = views.get(str(placement.get("right_view_id")))
        if left is None or right is None:
            continue
        left_affine = _affine_register_address(left.get("base_expression"))
        right_affine = _affine_register_address(right.get("base_expression"))
        if left_affine is None or right_affine is None:
            continue
        left_register, left_offset = left_affine
        right_register, right_offset = right_affine
        delta = (
            int(placement.get("byte_offset", 0))
            if placement.get("relation") == "right_base_equals_left_base_plus"
            else 0
        )
        values = dict(registers)
        if left_register == right_register:
            if (left_offset + delta - right_offset) & 0xFFFFFFFF:
                continue
        else:
            values[left_register] = (0x71000000 + index * 0x1000) & 0xFFFFFFFF
            left_address = (values[left_register] + left_offset) & 0xFFFFFFFF
            values[right_register] = (
                left_address + delta - right_offset
            ) & 0xFFFFFFFF
        key = tuple(sorted((name, int(values[name])) for name in {left_register, right_register}))
        if key in seen:
            continue
        seen.add(key)
        result.append(
            _case(
                f"memory-{raw['scenario']}-{index:04d}",
                values,
                flags,
                _initial_memory_for_contract(contract, values),
            )
        )
    return result


def _atomic_validation_cases(
    *,
    cluster: Mapping[str, Any],
    registers: Mapping[str, int],
    flags: Mapping[str, int],
) -> list[dict[str, Any]]:
    result = []
    contract = cluster.get("typed_contract", {})
    if not isinstance(contract, Mapping) or not contract.get("atomic_effects"):
        return result
    for effect_index, field in enumerate(_manual_atomic_fields(cluster)):
        try:
            address = _evaluate_semantic_address(
                field["address_expression"], registers
            )
            expected = _evaluate_semantic_address(
                field["expected_expression"], registers
            )
        except StageAInputError:
            continue
        observed_values = (expected, (expected + 1) & 0xFFFFFFFF, 0xFFFFFFFF)
        for value_index, observed in enumerate(dict.fromkeys(observed_values)):
            memory = _initial_memory_for_contract(contract, registers)
            memory = _add_initial_memory_word(memory, address, observed)
            result.append(
                _case(
                    f"atomic-{effect_index:02d}-{value_index:02d}",
                    registers,
                    flags,
                    memory,
                )
            )
    return result


def _affine_register_address(expression: Any) -> tuple[str, int] | None:
    register: str | None = None
    offset = 0

    def visit(value: Any) -> bool:
        nonlocal register, offset
        if not isinstance(value, Mapping):
            return False
        op = value.get("op")
        if op == "reg" and str(value.get("name")) in _REGISTERS:
            name = str(value["name"])
            if register is not None and register != name:
                return False
            register = name
            return True
        if op == "const" and isinstance(value.get("value"), int):
            offset = (offset + int(value["value"])) & 0xFFFFFFFF
            return True
        if op in {"add", "add32"} and isinstance(value.get("args"), list):
            return all(visit(child) for child in value["args"])
        return False

    if not visit(expression) or register is None:
        return None
    return register, offset


def _add_initial_memory_word(
    memory: Sequence[Mapping[str, Any]], address: int, value: int
) -> list[dict[str, Any]]:
    bytes_by_address: dict[int, int] = {}
    for span in memory:
        raw = bytes.fromhex(str(span["bytes"]))
        start = int(span["address"])
        for offset, byte in enumerate(raw):
            bytes_by_address[(start + offset) & 0xFFFFFFFF] = byte
    for offset, byte in enumerate((value & 0xFFFFFFFF).to_bytes(4, "little")):
        bytes_by_address[(address + offset) & 0xFFFFFFFF] = byte
    if not bytes_by_address:
        return []
    result = []
    addresses = sorted(bytes_by_address)
    start = addresses[0]
    previous = start
    values = [bytes_by_address[start]]
    for current in addresses[1:]:
        if current == previous + 1:
            values.append(bytes_by_address[current])
        else:
            result.append({"address": start, "bytes": bytes(values).hex()})
            start = current
            values = [bytes_by_address[current]]
        previous = current
    result.append({"address": start, "bytes": bytes(values).hex()})
    return result


def _initial_memory_for_contract(
    contract: Mapping[str, Any], registers: Mapping[str, int]
) -> list[dict[str, Any]]:
    result: dict[int, int] = {}
    for view in _validation_memory_views(contract):
        try:
            base = _evaluate_semantic_address(view["base_expression"], registers)
        except StageAInputError:
            continue
        for offset in range(int(view["byte_length"])):
            result.setdefault((base + offset) & 0xFFFFFFFF, 0xA5)
    if not result:
        return []
    addresses = sorted(result)
    spans = []
    start = addresses[0]
    values = [result[start]]
    previous = start
    for address in addresses[1:]:
        if address == previous + 1:
            values.append(result[address])
        else:
            spans.append({"address": start, "bytes": bytes(values).hex()})
            start = address
            values = [result[address]]
        previous = address
    spans.append({"address": start, "bytes": bytes(values).hex()})
    return spans


def _evaluate_semantic_address(
    expression: Any, registers: Mapping[str, int]
) -> int:
    if not isinstance(expression, Mapping):
        raise StageAInputError("memory address expression is not normalized")
    op = expression.get("op")
    if op == "reg" and str(expression.get("name")) in registers:
        return int(registers[str(expression["name"])]) & 0xFFFFFFFF
    if op == "const" and isinstance(expression.get("value"), int):
        return int(expression["value"]) & 0xFFFFFFFF
    binary = {
        "add": lambda left, right: left + right,
        "add32": lambda left, right: left + right,
        "sub": lambda left, right: left - right,
        "sub32": lambda left, right: left - right,
        "mul": lambda left, right: left * right,
        "mul32": lambda left, right: left * right,
        "and": lambda left, right: left & right,
        "and32": lambda left, right: left & right,
        "or": lambda left, right: left | right,
        "or32": lambda left, right: left | right,
        "xor": lambda left, right: left ^ right,
        "xor32": lambda left, right: left ^ right,
    }.get(str(op))
    if binary is not None:
        args = expression.get("args")
        if isinstance(args, list) and len(args) == 2:
            left = _evaluate_semantic_address(args[0], registers)
            right = _evaluate_semantic_address(args[1], registers)
            return binary(left, right) & 0xFFFFFFFF
    raise StageAInputError("memory address expression needs manual case placement")


def _synthesize_cluster_validation(
    cluster: Mapping[str, Any], units: Sequence[Mapping[str, Any]]
) -> dict[str, Any]:
    branches = [
        edge["condition"]
        for unit in units
        for edge in unit.get("semantics", {}).get("edge_conditions", [])
        if isinstance(edge, Mapping) and isinstance(edge.get("condition"), Mapping)
    ]
    indirect_domains = []
    for index, control in enumerate(cluster.get("control", [])):
        if not isinstance(control, Mapping):
            continue
        entries = control.get("dispatch_entries")
        if not isinstance(entries, list) or not entries:
            continue
        target_units_by_rva = {
            int(rva): str(unit_id)
            for unit_id, rva in zip(
                control.get("target_unit_ids", []),
                control.get("target_rvas", []),
                strict=False,
            )
        }
        table = (
            control["table"] if isinstance(control.get("table"), Mapping) else {}
        )
        selector = (
            control["selector"]
            if isinstance(control.get("selector"), Mapping)
            else {}
        )
        selector_expression = selector.get("expression")
        input_name, input_width, executable_binding = _dispatch_input_binding(
            selector_expression, index
        )
        domain = [
            {
                "target_rva": int(entry["target_rva"]),
                "target_unit_id": target_units_by_rva.get(
                    int(entry["target_rva"])
                ),
                "case_indices": [int(entry["index"])],
                "table_entry_rva": int(entry["entry_rva"]),
                "table_entry_address": (
                    int(table["address"])
                    + int(entry["index"]) * int(table.get("entry_width", 4))
                    if isinstance(table.get("address"), int)
                    else None
                ),
                "target_address": int(entry["target_address"]),
            }
            for entry in entries
        ]
        indirect_domains.append(
            {
                "domain": domain,
                "input_name": input_name,
                "input_width": input_width,
                "selector_expression": copy.deepcopy(selector_expression),
                "executable_binding": executable_binding,
            }
        )
    synthesis = synthesize_reconstruction_validation(
        expressions=_semantic_expressions(units),
        branches=branches,
        indirect_domains=indirect_domains,
        memory_views=_validation_memory_views(cluster.get("typed_contract", {})),
    ).to_payload()
    bindings = {
        str(spec["input_name"]): {
            "selector_expression": copy.deepcopy(spec["selector_expression"]),
            "executable": bool(spec["executable_binding"]),
        }
        for spec in indirect_domains
    }
    for case in synthesis["indirect_dispatch_cases"]:
        input_names = list(case.get("inputs", {}))
        if len(input_names) == 1 and input_names[0] in bindings:
            case["dispatch_binding"] = copy.deepcopy(bindings[input_names[0]])
    synthesis["format"] = RECONSTRUCTION_VALIDATION_CASES_FORMAT
    synthesis["cluster_id"] = cluster["id"]
    return synthesis


def _dispatch_input_binding(
    expression: Any, domain_index: int
) -> tuple[str, int, bool]:
    registers: set[str] = set()

    def visit(value: Any) -> None:
        if isinstance(value, Mapping):
            if value.get("op") == "reg" and isinstance(value.get("name"), str):
                registers.add(str(value["name"]).lower())
            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    visit(expression)
    if len(registers) != 1:
        return f"dispatch_selector_{domain_index}", 32, False
    raw = next(iter(registers))
    parent = {
        "al": "eax", "ah": "eax", "ax": "eax",
        "bl": "ebx", "bh": "ebx", "bx": "ebx",
        "cl": "ecx", "ch": "ecx", "cx": "ecx",
        "dl": "edx", "dh": "edx", "dx": "edx",
        "si": "esi", "di": "edi", "bp": "ebp", "sp": "esp",
    }.get(raw, raw)
    if parent not in _REGISTERS:
        return f"dispatch_selector_{domain_index}", 32, False
    # Recovery has already proved the finite selector range.  Binding the
    # parent register to the selector is executable for direct, low-part, and
    # low-mask forms; reject all other expression shapes here.
    supported = _selector_is_identity_on_small_values(expression, raw)
    return (parent if supported else f"dispatch_selector_{domain_index}", 32, supported)


def _selector_is_identity_on_small_values(expression: Any, register: str) -> bool:
    if not isinstance(expression, Mapping):
        return False
    op = expression.get("op")
    if op == "reg":
        return str(expression.get("name", "")).lower() == register
    if op in {"truncate", "zero_extend", "zeroextend", "zext"}:
        args = expression.get("args")
        child = args[0] if isinstance(args, list) and args else expression.get("value")
        return _selector_is_identity_on_small_values(child, register)
    if op in {"and", "and32"}:
        args = expression.get("args")
        if not isinstance(args, list) or len(args) != 2:
            return False
        constants = [
            int(arg["value"])
            for arg in args
            if isinstance(arg, Mapping)
            and arg.get("op") == "const"
            and isinstance(arg.get("value"), int)
        ]
        dynamic = [arg for arg in args if not (
            isinstance(arg, Mapping)
            and arg.get("op") == "const"
            and isinstance(arg.get("value"), int)
        )]
        return (
            len(constants) == 1
            and constants[0] & 0xFF == 0xFF
            and len(dynamic) == 1
            and _selector_is_identity_on_small_values(dynamic[0], register)
        )
    return False


def _validation_memory_views(contract: Mapping[str, Any]) -> list[dict[str, Any]]:
    result = []
    for view in contract.get("memory_views", []):
        if not isinstance(view, Mapping) or not isinstance(view.get("base"), Mapping):
            continue
        for field in view.get("fields", []):
            if not isinstance(field, Mapping):
                continue
            accesses = set(str(value) for value in field.get("accesses", []))
            access = (
                "read_write"
                if {"read", "write"} <= accesses or "read_write" in accesses
                else "write" if "write" in accesses else "read"
            )
            base = copy.deepcopy(view["base"])
            offset = int(field.get("offset", 0))
            if offset:
                base = {
                    "op": "add32",
                    "args": [
                        base,
                        {"op": "const", "value": offset & 0xFFFFFFFF, "width": 32},
                    ],
                }
            result.append(
                {
                    "id": str(field.get("id") or f"{view['id']}:offset:{offset}"),
                    "base_expression": base,
                    "byte_length": int(field["width_bytes"]),
                    "length_expression": None,
                    "access": access,
                }
            )
    return result


def _mutation_inventory(units: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    mutations: dict[str, dict[str, Any]] = {}

    def add(kind: str, unit: Mapping[str, Any], location: str, action: str) -> None:
        body = {
            "kind": kind,
            "unit_id": str(unit["id"]),
            "rva_start": int(_source_span(unit)["rva_start"]),
            "semantic_location": location,
            "mutation": action,
            "expected": "candidate-only validation must report violated",
        }
        body["id"] = "mutation:" + _canonical_sha256(body)[:20]
        mutations[body["id"]] = body

    def visit(unit: Mapping[str, Any], value: Any, path: str) -> None:
        if isinstance(value, Mapping):
            op = value.get("op")
            if op in {"eq", "ult32", "and_bool", "or_bool", "not"}:
                add("predicate", unit, path, "invert predicate result")
            if op == "const" and isinstance(value.get("value"), int):
                add("constant", unit, path, "replace constant with its +/-1 neighbors")
            for key, child in value.items():
                visit(unit, child, f"{path}/{key}")
        elif isinstance(value, list):
            for index, child in enumerate(value):
                visit(unit, child, f"{path}/{index}")

    for unit in units:
        semantics = unit.get("semantics", {})
        visit(unit, semantics, "/semantics")
        for index, _event in enumerate(semantics.get("memory_events", [])):
            add("memory_effect", unit, f"/semantics/memory_events/{index}", "drop or resize the memory effect")
        for index, _event in enumerate(semantics.get("external_events", [])):
            add("external_protocol", unit, f"/semantics/external_events/{index}", "alter API identity, argument, or callback contract")
        outcome = semantics.get("outcome", {})
        if isinstance(outcome, Mapping) and outcome.get("kind") == "branch":
            add("control", unit, "/semantics/outcome", "swap the true and false targets")
    return [mutations[key] for key in sorted(mutations)]


def _render_regional_harness(
    manifest: RegionReplacementManifest,
    cases: Mapping[str, Any],
    *,
    fallback_on_unimplemented: bool = False,
    typed_x87_runtime: bool = False,
) -> str:
    symbol = str(manifest.source["symbol"])
    cluster_entry_rvas = sorted(
        {
            int(span["start"])
            for span in manifest.cluster["rva_spans"]
            if isinstance(span, Mapping) and isinstance(span.get("start"), int)
        }
    )
    if int(manifest.cluster["entry_rva"]) not in cluster_entry_rvas:
        raise StageAInputError("regional harness cluster omits its entry RVA span")
    cluster_rva_cases = " ".join(
        f"case UINT32_C(0x{rva:08x}):" for rva in cluster_entry_rvas
    )
    address_space = cases.get("address_space")
    if address_space is None:
        image_base = 0
        image_size = 0
    else:
        address_space = _object(address_space, "reconstruction case address space")
        if set(address_space) != {"kind", "image_base", "size_of_image"}:
            raise StageAInputError("reconstruction case address space is malformed")
        if address_space.get("kind") != "pe32_image_rva_v1":
            raise StageAInputError("unsupported reconstruction case address space")
        image_base = int(address_space["image_base"])
        image_size = int(address_space["size_of_image"])
        if (
            image_base < 0
            or image_size <= 0
            or image_base + image_size > 1 << 32
        ):
            raise StageAInputError("reconstruction case PE32 address space is invalid")
    case_rows = _array(cases.get("cases"), "reconstruction cases")
    event_capacity = max(
        16,
        *(
            len(
                _array(
                    _object(row, "reconstruction case").get(
                        "external_responses", []
                    ),
                    "case external responses",
                )
            )
            for row in case_rows
        ),
    )
    if event_capacity > 256:
        raise StageAInputError(
            "regional harness requires more than 256 external-event records"
        )
    call_stack_observations = _regional_call_stack_observations(cases)
    call_stack_observation_lines = []
    for event_index, slots in call_stack_observations:
        call_stack_observation_lines.append(
            f"  if (event_index == {event_index}U) {{"
        )
        for offset, width in slots:
            call_stack_observation_lines.extend(
                [
                    "    if (!harness_observe_stack_input(",
                    "        context, record, input, "
                    f"UINT32_C(0x{offset:08x}), {width}U))",
                    "      return STAGE_B_CALL_MEMORY_FAULT;",
                ]
            )
        call_stack_observation_lines.append("  }")
    fallback_lines = (
        [
            "  if (replacement_result.kind == STAGE_B_UNIMPLEMENTED) {",
            "    replacement_state = *initial;",
            "    initialize_context(&replacement_context, bytes, byte_count, responses, response_count);",
            "    replacement_result = run_baseline_cluster(&replacement_runtime, &replacement_state);",
            "  }",
        ]
        if fallback_on_unimplemented
        else []
    )
    initializers = []
    invocations = []
    for index, raw_case in enumerate(case_rows):
        case = _object(raw_case, f"reconstruction case {index}")
        registers = _object(case.get("registers"), f"case {index} registers")
        flags = _object(case.get("flags"), f"case {index} flags")
        memory = _array(case.get("memory"), f"case {index} memory")
        responses = _array(
            case.get("external_responses", []),
            f"case {index} external responses",
        )
        if len(responses) > event_capacity:
            raise StageAInputError(
                f"case {index} has more external responses than the regional harness can record"
            )
        state_values = [
            ".%s = UINT32_C(0x%08x)" % (name, int(registers[name]) & 0xFFFFFFFF)
            for name in _REGISTERS
        ]
        state_values.extend(
            ".%s = UINT32_C(0x%08x)" % (name, int(flags[name]) & 0xFFFFFFFF)
            for name in _FLAGS
        )
        if typed_x87_runtime:
            state_values.extend(
                [
                    ".x87_stack = {"
                    + ", ".join(
                        "{ .empty = 1U, .tag = 3U }" for _ in range(8)
                    )
                    + "}",
                    ".x87_control = UINT16_C(0x037f)",
                ]
            )
        state_values.extend(
            [
                ".original_rva = UINT32_C(0x%08x)"
                % (int(manifest.cluster["entry_rva"]) & 0xFFFFFFFF),
            ]
        )
        initializers.append(
            "  static const stage_b_machine_state state_%u = { %s };"
            % (index, ", ".join(state_values))
        )
        bytes_rows = []
        for item in memory:
            cell = _object(item, f"case {index} memory cell")
            address = int(cell["address"])
            raw = bytes.fromhex(str(cell["bytes"]))
            bytes_rows.extend((address + offset, value) for offset, value in enumerate(raw))
        if bytes_rows:
            initializers.append(
                "  static const harness_initial_byte memory_%u[] = { %s };"
                % (
                    index,
                    ", ".join(
                        "{ UINT32_C(0x%08x), UINT8_C(0x%02x) }" % item
                        for item in bytes_rows
                    ),
                )
            )
            memory_pointer = f"memory_{index}"
        else:
            memory_pointer = "0"
        view_rows = []
        for view in manifest.payload["memory_views"]:
            base = _evaluate_base_expression(str(view["base_expression"]), registers)
            view_rows.append(
                "{ UINT32_C(0x%08x), %uU }" % (base, int(view["byte_length"]))
            )
        if view_rows:
            initializers.append(
                "  static const harness_view views_%u[] = { %s };"
                % (index, ", ".join(view_rows))
            )
            views_pointer = f"views_{index}"
        else:
            views_pointer = "0"
        response_values = []
        for response_index, raw_response in enumerate(responses):
            response = _object(
                raw_response,
                f"case {index} external response {response_index}",
            )
            if set(response) - {"eax", "registers", "flags", "memory_writes"} or "eax" not in response:
                raise StageAInputError(
                    "regional external response requires EAX and optional register, flag, and memory effects"
                )
            response_registers = _object(
                response.get("registers", {}),
                f"case {index} external response {response_index} registers",
            )
            if set(response_registers) - set(_REGISTERS):
                raise StageAInputError(
                    "regional external response names an unsupported register"
                )
            register_values = {"eax": int(response["eax"])}
            register_values.update(
                {str(name): int(value) for name, value in response_registers.items()}
            )
            if any(not 0 <= value <= 0xFFFFFFFF for value in register_values.values()):
                raise StageAInputError(
                    "regional external response register value is outside PE32"
                )
            response_flags = _object(
                response.get("flags", {}),
                f"case {index} external response {response_index} flags",
            )
            if set(response_flags) - set(_FLAGS) or any(
                int(value) not in {0, 1} for value in response_flags.values()
            ):
                raise StageAInputError(
                    "regional external response flag effect is malformed"
                )
            response_writes = _array(
                response.get("memory_writes", []),
                f"case {index} external response {response_index} memory writes",
            )
            if len(response_writes) > 16:
                raise StageAInputError(
                    "regional external response exceeds the memory-write count limit"
                )
            write_rows = []
            total_write_bytes = 0
            for write_index, raw_write in enumerate(response_writes):
                write = _object(
                    raw_write,
                    f"case {index} external response {response_index} memory write {write_index}",
                )
                if set(write) not in (
                    {"argument_index", "offset", "bytes"},
                    {"stack_pointer_offset", "offset", "bytes"},
                ):
                    raise StageAInputError(
                        "regional external response memory write is malformed"
                    )
                if "argument_index" in write:
                    location_kind = 0
                    location_value = int(write["argument_index"])
                    valid_location = 0 <= location_value < 16
                else:
                    location_kind = 1
                    location_value = int(write["stack_pointer_offset"])
                    valid_location = 0 <= location_value <= 0xFFFFFFFF
                offset = int(write["offset"])
                if not valid_location or not 0 <= offset <= 0xFFFFFFFF:
                    raise StageAInputError(
                        "regional external response memory-write location is invalid"
                    )
                try:
                    write_bytes = bytes.fromhex(str(write["bytes"]))
                except ValueError as error:
                    raise StageAInputError(
                        "regional external response memory-write bytes are invalid"
                    ) from error
                if not write_bytes:
                    raise StageAInputError(
                        "regional external response memory write must not be empty"
                    )
                total_write_bytes += len(write_bytes)
                if total_write_bytes > 512:
                    raise StageAInputError(
                        "regional external response exceeds the memory-write byte limit"
                    )
                byte_name = f"response_{index}_{response_index}_write_{write_index}_bytes"
                initializers.append(
                    "  static const uint8_t %s[] = { %s };"
                    % (
                        byte_name,
                        ", ".join(
                            f"UINT8_C(0x{value:02x})" for value in write_bytes
                        ),
                    )
                )
                write_rows.append(
                    "{ %uU, UINT32_C(0x%08x), UINT32_C(0x%08x), %s, %uU }"
                    % (
                        location_kind,
                        location_value,
                        offset,
                        byte_name,
                        len(write_bytes),
                    )
                )
            if write_rows:
                writes_name = f"response_{index}_{response_index}_writes"
                initializers.append(
                    "  static const harness_response_write %s[] = { %s };"
                    % (writes_name, ", ".join(write_rows))
                )
                writes_pointer = writes_name
            else:
                writes_pointer = "0"
            response_values.append(
                "{ { %s }, UINT32_C(0x%08x), { %s }, UINT32_C(0x%08x), %s, %uU }"
                % (
                    ", ".join(
                        "UINT32_C(0x%08x)" % (register_values.get(name, 0) & 0xFFFFFFFF)
                        for name in _REGISTERS
                    ),
                    sum(
                        1 << register_index
                        for register_index, name in enumerate(_REGISTERS)
                        if name in register_values
                    ),
                    ", ".join(
                        "UINT32_C(0x%08x)" % int(response_flags.get(name, 0))
                        for name in _FLAGS
                    ),
                    sum(
                        1 << flag_index
                        for flag_index, name in enumerate(_FLAGS)
                        if name in response_flags
                    ),
                    writes_pointer,
                    len(write_rows),
                )
            )
        if response_values:
            initializers.append(
                "  static const harness_response responses_%u[] = { %s };"
                % (
                    index,
                    ", ".join(response_values),
                )
            )
            responses_pointer = f"responses_{index}"
        else:
            responses_pointer = "0"
        invocations.append(
            "  run_case(%uU, &state_%u, %s, %uU, %s, %uU, %s, %uU);"
            % (
                index,
                index,
                memory_pointer,
                len(bytes_rows),
                views_pointer,
                len(view_rows),
                responses_pointer,
                len(response_values),
            )
        )
    return "\n".join(
        [
            "#include <stdint.h>",
            "#include <stdio.h>",
            "#include <string.h>",
            '#include "state-machine-interpreter.h"',
            "",
            f"stage_b_step_result {symbol}(stage_b_runtime *, stage_b_machine_state *);",
            "",
            "typedef struct harness_initial_byte { uint32_t address; uint8_t value; } harness_initial_byte;",
            "typedef struct harness_view { uint32_t address; uint32_t width; } harness_view;",
            "typedef struct harness_byte { uint32_t address; uint8_t value; } harness_byte;",
            "typedef struct harness_response_write {",
            "  uint32_t location_kind, location_value, offset;",
            "  const uint8_t *bytes;",
            "  uint32_t byte_count;",
            "} harness_response_write;",
            "typedef struct harness_response {",
            "  uint32_t registers[8], register_mask;",
            "  uint32_t flags[6], flag_mask;",
            "  const harness_response_write *writes;",
            "  uint32_t write_count;",
            "} harness_response;",
            "typedef struct harness_event {",
            "  char identity[192];",
            "  uint32_t kind, instruction_rva, call_index, target_rva, return_rva;",
            "  uint32_t ordinal, has_ordinal;",
            "  uint32_t arguments[16];",
            "  uint32_t argument_count;",
            "  stage_b_stack_input stack_inputs[16];",
            "  uint32_t stack_input_count;",
            "  uint32_t registers[8];",
            "  uint32_t flags[6];",
            "} harness_event;",
            "typedef struct harness_context {",
            "  harness_byte bytes[512];",
            "  uint32_t byte_count;",
            "  harness_byte writes[512];",
            "  uint32_t write_count;",
            "  uint32_t write_overflow;",
            f"  harness_event events[{event_capacity}];",
            "  uint32_t event_count;",
            "  uint32_t event_overflow;",
            "  const harness_response *responses;",
            "  uint32_t response_count;",
            "} harness_context;",
            "",
            "static int find_byte(harness_context *context, uint32_t address) {",
            "  uint32_t index;",
            "  for (index = 0U; index < context->byte_count; ++index)",
            "    if (context->bytes[index].address == address) return (int)index;",
            "  return -1;",
            "}",
            "",
            "static int find_write(harness_context *context, uint32_t address) {",
            "  uint32_t index;",
            "  for (index = 0U; index < context->write_count; ++index)",
            "    if (context->writes[index].address == address) return (int)index;",
            "  return -1;",
            "}",
            "",
            "static uint32_t harness_read(void *opaque, uint32_t address, uint32_t width, uint32_t *fault) {",
            "  harness_context *context = (harness_context *)opaque;",
            "  uint32_t result = 0U, offset;",
            "  if (width == 0U || width > 4U) { *fault = 1U; return 0U; }",
            "  for (offset = 0U; offset < width; ++offset) {",
            "    int index = find_byte(context, address + offset);",
            "    if (index < 0) { *fault = 1U; return 0U; }",
            "    result |= ((uint32_t)context->bytes[index].value) << (8U * offset);",
            "  }",
            "  return result;",
            "}",
            "",
            "static void harness_write(void *opaque, uint32_t address, uint32_t width, uint32_t value, uint32_t *fault) {",
            "  harness_context *context = (harness_context *)opaque;",
            "  uint32_t offset;",
            "  if (width == 0U || width > 4U) { *fault = 1U; return; }",
            "  for (offset = 0U; offset < width; ++offset) {",
            "    int index = find_byte(context, address + offset);",
            "    if (index < 0) {",
            "      if (context->byte_count >= 512U) { *fault = 1U; return; }",
            "      index = (int)context->byte_count++;",
            "      context->bytes[index].address = address + offset;",
            "    }",
            "    context->bytes[index].value = (uint8_t)(value >> (8U * offset));",
            "    index = find_write(context, address + offset);",
            "    if (index < 0) {",
            "      if (context->write_count >= 512U) { context->write_overflow = 1U; continue; }",
            "      index = (int)context->write_count++;",
            "      context->writes[index].address = address + offset;",
            "    }",
            "    context->writes[index].value = (uint8_t)(value >> (8U * offset));",
            "  }",
            "}",
            "",
            "#ifdef STAGE_B_MACHINE_STATE_HAS_X87",
            "static uint32_t harness_x87_register(const stage_b_machine_state *state, uint32_t code, uint32_t *valid) {",
            "  *valid = 1U;",
            "  switch (code) {",
            "  case 0U: return 0U; case 1U: return state->eax; case 2U: return state->ebx;",
            "  case 3U: return state->ecx; case 4U: return state->edx; case 5U: return state->esi;",
            "  case 6U: return state->edi; case 7U: return state->ebp; case 8U: return state->esp;",
            "  default: *valid = 0U; return 0U;",
            "  }",
            "}",
            "",
            "static uint32_t harness_x87_address(const stage_b_typed_x87_operation *program,",
            "    const stage_b_machine_state *state, uint32_t *valid) {",
            "  uint32_t base, index;",
            "  if (program->has_image_rva != 0U) {",
            "    if (program->base_register != 0U || program->index_register != 0U ||",
            "        program->displacement != 0) { *valid = 0U; return 0U; }",
            "    *valid = 1U; return program->image_base + program->image_rva;",
            "  }",
            "  base = harness_x87_register(state, program->base_register, valid);",
            "  if (!*valid) return 0U;",
            "  index = harness_x87_register(state, program->index_register, valid);",
            "  if (!*valid || (program->scale != 1U && program->scale != 2U &&",
            "      program->scale != 4U && program->scale != 8U)) return 0U;",
            "  return base + index * program->scale + (uint32_t)program->displacement;",
            "}",
            "",
            "static void harness_x87_set_bytes(stage_b_x87_value *value, uint64_t significand, uint16_t sign_exponent) {",
            "  uint32_t index;",
            "  for (index = 0U; index < 8U; ++index)",
            "    value->value_bytes[index] = (uint8_t)(significand >> (8U * index));",
            "  value->value_bytes[8] = (uint8_t)sign_exponent;",
            "  value->value_bytes[9] = (uint8_t)(sign_exponent >> 8U);",
            "}",
            "",
            "static uint64_t harness_x87_significand(const stage_b_x87_value *value) {",
            "  uint64_t result = 0U; uint32_t index;",
            "  for (index = 0U; index < 8U; ++index)",
            "    result |= (uint64_t)value->value_bytes[index] << (8U * index);",
            "  return result;",
            "}",
            "",
            "static uint16_t harness_x87_sign_exponent(const stage_b_x87_value *value) {",
            "  return (uint16_t)((uint16_t)value->value_bytes[8] |",
            "      ((uint16_t)value->value_bytes[9] << 8U));",
            "}",
            "",
            "static void harness_x87_from_fp64(uint64_t bits, stage_b_x87_value *value) {",
            "  uint64_t fraction = bits & UINT64_C(0x000fffffffffffff);",
            "  uint32_t exponent = (uint32_t)((bits >> 52U) & UINT64_C(0x7ff));",
            "  uint16_t sign = (uint16_t)((bits >> 48U) & UINT64_C(0x8000));",
            "  uint64_t significand; uint16_t extended_exponent; uint32_t highest;",
            "  if (exponent == 0U && fraction == 0U) { significand = 0U; extended_exponent = 0U; value->tag = 1U; }",
            "  else if (exponent == 0U) {",
            "    highest = 0U; while ((fraction >> (highest + 1U)) != 0U) ++highest;",
            "    significand = fraction << (63U - highest);",
            "    extended_exponent = (uint16_t)((int32_t)highest - 1074 + 16383); value->tag = 0U;",
            "  } else if (exponent == 0x7ffU) {",
            "    significand = UINT64_C(0x8000000000000000) | (fraction << 11U);",
            "    extended_exponent = UINT16_C(0x7fff); value->tag = 2U;",
            "  } else {",
            "    significand = UINT64_C(0x8000000000000000) | (fraction << 11U);",
            "    extended_exponent = (uint16_t)((int32_t)exponent - 1023 + 16383); value->tag = 0U;",
            "  }",
            "  harness_x87_set_bytes(value, significand, (uint16_t)(sign | extended_exponent));",
            "  value->empty = 0U;",
            "}",
            "",
            "static uint32_t harness_x87_to_fp64(const stage_b_x87_value *value, uint64_t *bits) {",
            "  const uint64_t fraction_mask = UINT64_C(0x000fffffffffffff);",
            "  uint64_t significand = harness_x87_significand(value), fraction;",
            "  uint16_t sign_exponent = harness_x87_sign_exponent(value);",
            "  uint32_t exponent = sign_exponent & UINT16_C(0x7fff);",
            "  uint64_t sign = (uint64_t)(sign_exponent & UINT16_C(0x8000)) << 48U;",
            "  int32_t unbiased; uint32_t shift;",
            "  if (value->empty != 0U) return 0U;",
            "  if (exponent == 0U) { if (significand != 0U) return 0U; *bits = sign; return 1U; }",
            "  if (exponent == 0x7fffU) {",
            "    if ((significand & UINT64_C(0x8000000000000000)) == 0U || (significand & UINT64_C(0x7ff)) != 0U) return 0U;",
            "    fraction = (significand >> 11U) & fraction_mask;",
            "    *bits = sign | UINT64_C(0x7ff0000000000000) | fraction; return 1U;",
            "  }",
            "  if ((significand & UINT64_C(0x8000000000000000)) == 0U) return 0U;",
            "  unbiased = (int32_t)exponent - 16383;",
            "  if (unbiased >= -1022 && unbiased <= 1023) {",
            "    if ((significand & UINT64_C(0x7ff)) != 0U) return 0U;",
            "    fraction = (significand >> 11U) & fraction_mask;",
            "    *bits = sign | ((uint64_t)(unbiased + 1023) << 52U) | fraction; return 1U;",
            "  }",
            "  if (unbiased < -1074 || unbiased >= -1022) return 0U;",
            "  shift = (uint32_t)(63 - (unbiased + 1074));",
            "  if (shift >= 64U || (significand & ((UINT64_C(1) << shift) - 1U)) != 0U) return 0U;",
            "  fraction = significand >> shift; if (fraction > fraction_mask) return 0U;",
            "  *bits = sign | fraction; return 1U;",
            "}",
            "",
            "static uint32_t harness_x87_push(stage_b_machine_state *state, stage_b_x87_value value) {",
            "  uint32_t index, top; if (state->x87_stack[7].empty == 0U) return 0U;",
            "  for (index = 7U; index > 0U; --index) state->x87_stack[index] = state->x87_stack[index - 1U];",
            "  state->x87_stack[0] = value; top = ((state->x87_status >> 11U) + 7U) & 7U;",
            "  state->x87_status = (uint16_t)((state->x87_status & UINT16_C(0xc7ff)) | (uint16_t)(top << 11U));",
            "  return 1U;",
            "}",
            "",
            "static uint32_t harness_x87_pop(stage_b_machine_state *state) {",
            "  uint32_t index, top; if (state->x87_stack[0].empty != 0U) return 0U;",
            "  for (index = 0U; index < 7U; ++index) state->x87_stack[index] = state->x87_stack[index + 1U];",
            "  memset(&state->x87_stack[7], 0, sizeof(state->x87_stack[7]));",
            "  state->x87_stack[7].empty = 1U; state->x87_stack[7].tag = 3U;",
            "  top = ((state->x87_status >> 11U) + 1U) & 7U;",
            "  state->x87_status = (uint16_t)((state->x87_status & UINT16_C(0xc7ff)) | (uint16_t)(top << 11U));",
            "  return 1U;",
            "}",
            "",
            "static stage_b_call_status harness_execute_typed_x87_operation(",
            "    stage_b_runtime *runtime, const stage_b_typed_x87_operation *program,",
            "    const stage_b_machine_state *input, stage_b_machine_state *output) {",
            "  uint32_t valid = 0U, fault = 0U, address, first, second; uint64_t bits;",
            "  stage_b_x87_value value, temporary;",
            "  if (runtime == 0 || program == 0 || input == 0 || output == 0 || program->mnemonic == 0)",
            "    return STAGE_B_CALL_UNIMPLEMENTED;",
            "  *output = *input;",
            "  if (program->operand_kind == 3U && program->operand_width == 8U && strcmp(program->mnemonic, \"fld\") == 0) {",
            "    address = harness_x87_address(program, input, &valid); if (!valid) return STAGE_B_CALL_UNIMPLEMENTED;",
            "    first = runtime->read(runtime->context, address, 4U, &fault);",
            "    second = runtime->read(runtime->context, address + 4U, 4U, &fault);",
            "    if (fault) return STAGE_B_CALL_MEMORY_FAULT; bits = first | ((uint64_t)second << 32U);",
            "    harness_x87_from_fp64(bits, &value); return harness_x87_push(output, value) ? STAGE_B_CALL_OK : STAGE_B_CALL_UNIMPLEMENTED;",
            "  }",
            "  if (program->operand_kind == 3U && program->operand_width == 8U && strcmp(program->mnemonic, \"fstp\") == 0) {",
            "    address = harness_x87_address(program, input, &valid); if (!valid || !harness_x87_to_fp64(&input->x87_stack[0], &bits)) return STAGE_B_CALL_UNIMPLEMENTED;",
            "    runtime->write(runtime->context, address, 4U, (uint32_t)bits, &fault);",
            "    runtime->write(runtime->context, address + 4U, 4U, (uint32_t)(bits >> 32U), &fault);",
            "    if (fault) return STAGE_B_CALL_MEMORY_FAULT; return harness_x87_pop(output) ? STAGE_B_CALL_OK : STAGE_B_CALL_UNIMPLEMENTED;",
            "  }",
            "  if (program->operand_kind == 2U && strcmp(program->mnemonic, \"fxch\") == 0 &&",
            "      program->stack_register_count == 2U && program->stack_register_0 < 8U && program->stack_register_1 < 8U) {",
            "    if (input->x87_stack[program->stack_register_0].empty != 0U || input->x87_stack[program->stack_register_1].empty != 0U) return STAGE_B_CALL_UNIMPLEMENTED;",
            "    temporary = output->x87_stack[program->stack_register_0];",
            "    output->x87_stack[program->stack_register_0] = output->x87_stack[program->stack_register_1];",
            "    output->x87_stack[program->stack_register_1] = temporary; return STAGE_B_CALL_OK;",
            "  }",
            "  if (program->operand_kind == 2U && strcmp(program->mnemonic, \"fstp\") == 0 &&",
            "      program->stack_register_count == 1U && program->stack_register_0 < 8U) {",
            "    if (input->x87_stack[0].empty != 0U) return STAGE_B_CALL_UNIMPLEMENTED;",
            "    output->x87_stack[program->stack_register_0] = input->x87_stack[0];",
            "    return harness_x87_pop(output) ? STAGE_B_CALL_OK : STAGE_B_CALL_UNIMPLEMENTED;",
            "  }",
            "  return STAGE_B_CALL_UNIMPLEMENTED;",
            "}",
            "#endif",
            "",
            "static void harness_atomic_compare_exchange_impl(",
            "    void *opaque, uint32_t address, uint32_t width,",
            "    uint32_t expected, uint32_t desired, uint32_t *observed,",
            "    uint32_t *exchanged, uint32_t *fault) {",
            "  uint32_t current = harness_read(opaque, address, width, fault);",
            "  if (*fault) return;",
            "  *observed = current;",
            "  *exchanged = current == expected;",
            "  harness_write(",
            "      opaque, address, width, *exchanged ? desired : current, fault);",
            "}",
            "",
            "static void harness_atomic_exchange_impl(",
            "    void *opaque, uint32_t address, uint32_t width,",
            "    uint32_t desired, uint32_t *observed, uint32_t *fault) {",
            "  uint32_t current = harness_read(opaque, address, width, fault);",
            "  if (*fault) return;",
            "  *observed = current;",
            "  harness_write(opaque, address, width, desired, fault);",
            "}",
            "",
            "static int harness_observe_stack_input(",
            "    harness_context *context, harness_event *record,",
            "    const stage_b_machine_state *input, uint32_t offset,",
            "    uint32_t width) {",
            "  uint32_t actual, fault = 0U, index;",
            "  if (offset > UINT32_MAX - input->esp) {",
            "    context->event_overflow = 1U; return 0;",
            "  }",
            "  actual = harness_read(context, input->esp + offset, width, &fault);",
            "  if (fault) { context->event_overflow = 1U; return 0; }",
            "  for (index = 0U; index < record->stack_input_count; ++index) {",
            "    stage_b_stack_input *item = &record->stack_inputs[index];",
            "    if (item->offset == offset && item->width == width) {",
            "      if (item->value != actual) { context->event_overflow = 1U; return 0; }",
            "      return 1;",
            "    }",
            "  }",
            "  if (record->stack_input_count >= 16U) {",
            "    context->event_overflow = 1U; return 0;",
            "  }",
            "  record->stack_inputs[record->stack_input_count++] =",
            "      (stage_b_stack_input){ offset, width, actual };",
            "  return 1;",
            "}",
            "",
            "void stage_b_runtime_atomic_compare_exchange(",
            "    stage_b_runtime *runtime, uint32_t address, uint32_t width,",
            "    uint32_t expected, uint32_t desired, uint32_t *observed,",
            "    uint32_t *exchanged, uint32_t *fault) {",
            "  if (fault == 0) return;",
            "  *fault = 1U;",
            "  if (runtime == 0 || observed == 0 || exchanged == 0) return;",
            "  *fault = 0U;",
            "  harness_atomic_compare_exchange_impl(",
            "      runtime->context, address, width, expected, desired,",
            "      observed, exchanged, fault);",
            "}",
            "",
            "void stage_b_runtime_atomic_exchange(",
            "    stage_b_runtime *runtime, uint32_t address, uint32_t width,",
            "    uint32_t desired, uint32_t *observed, uint32_t *fault) {",
            "  if (fault == 0) return;",
            "  *fault = 1U;",
            "  if (runtime == 0 || observed == 0) return;",
            "  *fault = 0U;",
            "  harness_atomic_exchange_impl(",
            "      runtime->context, address, width, desired, observed, fault);",
            "}",
            "",
            "static stage_b_call_status harness_external(",
            "    stage_b_runtime *runtime, const stage_b_call_event *event,",
            "    const stage_b_machine_state *input, stage_b_machine_state *output) {",
            "  harness_context *context = (harness_context *)runtime->context;",
            "  harness_event *record;",
            "  uint32_t event_index, index;",
            "  *output = *input;",
            "  event_index = context->event_count;",
            f"  if (context->event_count >= {event_capacity}U) {{",
            "    context->event_overflow = 1U;",
            "    context->event_count += 1U;",
            "    return STAGE_B_CALL_OK;",
            "  }",
            "  record = &context->events[context->event_count++];",
            "  if (event->kind == STAGE_B_CALL_INDIRECT)",
            "    snprintf(record->identity, sizeof(record->identity), \"indirect-call\");",
            "  else",
            "    snprintf(record->identity, sizeof(record->identity),",
            "        \"%s!%s\", event->dll ? event->dll : \"\", event->symbol ? event->symbol : \"\");",
            "  record->kind = (uint32_t)event->kind;",
            "  record->instruction_rva = event->instruction_rva;",
            "  record->call_index = event->call_index;",
            "  record->target_rva = event->target_rva;",
            "  record->return_rva = event->return_rva;",
            "  record->ordinal = event->ordinal;",
            "  record->has_ordinal = event->has_ordinal;",
            "  if (event->argument_count > 16U || event->stack_input_count > 16U)",
            "    context->event_overflow = 1U;",
            "  record->argument_count = event->argument_count < 16U ? event->argument_count : 16U;",
            "  for (index = 0U; index < record->argument_count; ++index)",
            "    record->arguments[index] = event->arguments[index];",
            "  record->stack_input_count = event->stack_input_count < 16U ? event->stack_input_count : 16U;",
            "  for (index = 0U; index < record->stack_input_count; ++index)",
            "    record->stack_inputs[index] = event->stack_inputs[index];",
            *call_stack_observation_lines,
            "  record->registers[0] = input->eax; record->registers[1] = input->ebx;",
            "  record->registers[2] = input->ecx; record->registers[3] = input->edx;",
            "  record->registers[4] = input->esi; record->registers[5] = input->edi;",
            "  record->registers[6] = input->ebp; record->registers[7] = input->esp;",
            "  record->flags[0] = input->cf; record->flags[1] = input->zf;",
            "  record->flags[2] = input->sf; record->flags[3] = input->of;",
            "  record->flags[4] = input->pf; record->flags[5] = input->df;",
            "  if (event_index < context->response_count) {",
            "    const harness_response *response = &context->responses[event_index];",
            "    if (response->register_mask & UINT32_C(0x01)) output->eax = response->registers[0];",
            "    if (response->register_mask & UINT32_C(0x02)) output->ebx = response->registers[1];",
            "    if (response->register_mask & UINT32_C(0x04)) output->ecx = response->registers[2];",
            "    if (response->register_mask & UINT32_C(0x08)) output->edx = response->registers[3];",
            "    if (response->register_mask & UINT32_C(0x10)) output->esi = response->registers[4];",
            "    if (response->register_mask & UINT32_C(0x20)) output->edi = response->registers[5];",
            "    if (response->register_mask & UINT32_C(0x40)) output->ebp = response->registers[6];",
            "    if (response->register_mask & UINT32_C(0x80)) output->esp = response->registers[7];",
            "    if (response->flag_mask & UINT32_C(0x01)) output->cf = response->flags[0];",
            "    if (response->flag_mask & UINT32_C(0x02)) output->zf = response->flags[1];",
            "    if (response->flag_mask & UINT32_C(0x04)) output->sf = response->flags[2];",
            "    if (response->flag_mask & UINT32_C(0x08)) output->of = response->flags[3];",
            "    if (response->flag_mask & UINT32_C(0x10)) output->pf = response->flags[4];",
            "    if (response->flag_mask & UINT32_C(0x20)) output->df = response->flags[5];",
            "#ifdef STAGE_B_MACHINE_STATE_HAS_EFLAGS",
            "    output->eflags =",
            "        (output->eflags & ~UINT32_C(0x00000cd5)) |",
            "        ((output->cf & 1U) << 0) | ((output->pf & 1U) << 2) |",
            "        ((output->zf & 1U) << 6) | ((output->sf & 1U) << 7) |",
            "        ((output->df & 1U) << 10) | ((output->of & 1U) << 11);",
            "#endif",
            "    for (index = 0U; index < response->write_count; ++index) {",
            "      const harness_response_write *write = &response->writes[index];",
            "      uint32_t base, address, byte_index, fault = 0U;",
            "      if (write->location_kind == 0U) {",
            "        if (write->location_value >= event->argument_count) {",
            "          context->event_overflow = 1U;",
            "          return STAGE_B_CALL_MEMORY_FAULT;",
            "        }",
            "        base = event->arguments[write->location_value];",
            "      } else if (write->location_kind == 1U) {",
            "        if (write->location_value > UINT32_MAX - input->esp) {",
            "          context->event_overflow = 1U;",
            "          return STAGE_B_CALL_MEMORY_FAULT;",
            "        }",
            "        base = harness_read(context, input->esp + write->location_value, 4U, &fault);",
            "        if (fault) {",
            "          context->event_overflow = 1U;",
            "          return STAGE_B_CALL_MEMORY_FAULT;",
            "        }",
            "      } else {",
            "        context->event_overflow = 1U;",
            "        return STAGE_B_CALL_MEMORY_FAULT;",
            "      }",
            "      if (write->offset > UINT32_MAX - base ||",
            "          (write->byte_count > 0U &&",
            "           write->byte_count - 1U > UINT32_MAX - (base + write->offset))) {",
            "        context->event_overflow = 1U;",
            "        return STAGE_B_CALL_MEMORY_FAULT;",
            "      }",
            "      address = base + write->offset;",
            "      for (byte_index = 0U; byte_index < write->byte_count; ++byte_index) {",
            "        harness_write(context, address + byte_index, 1U, write->bytes[byte_index], &fault);",
            "        if (fault) {",
            "          context->event_overflow = 1U;",
            "          return STAGE_B_CALL_MEMORY_FAULT;",
            "        }",
            "      }",
            "    }",
            "  }",
            "  return STAGE_B_CALL_OK;",
            "}",
            "",
            "stage_b_call_status stage_b_dispatch_external_call(",
            "    stage_b_runtime *runtime, const stage_b_call_event *event,",
            "    const stage_b_machine_state *input, stage_b_machine_state *output) {",
            "  if (!runtime || !runtime->external_call_fallback) return STAGE_B_CALL_UNIMPLEMENTED;",
            "  return runtime->external_call_fallback(runtime, event, input, output);",
            "}",
            "",
            "static void initialize_context(harness_context *context,",
            "    const harness_initial_byte *bytes, uint32_t count,",
            "    const harness_response *responses, uint32_t response_count) {",
            "  uint32_t index;",
            "  memset(context, 0, sizeof(*context));",
            "  for (index = 0U; index < count; ++index) {",
            "    context->bytes[index].address = bytes[index].address;",
            "    context->bytes[index].value = bytes[index].value;",
            "  }",
            "  context->byte_count = count;",
            "  context->responses = responses;",
            "  context->response_count = response_count;",
            "}",
            "",
            "static int cluster_contains_rva(uint32_t rva) {",
            f"  switch (rva) {{ {cluster_rva_cases} return 1; default: return 0; }}",
            "}",
            "",
            "static int image_address_to_rva(uint32_t address, uint32_t *rva) {",
            f"  const uint32_t image_base = UINT32_C(0x{image_base:08x});",
            f"  const uint32_t image_size = UINT32_C(0x{image_size:08x});",
            "  if (rva == 0 || image_size == 0U || address < image_base ||",
            "      address - image_base >= image_size)",
            "    return 0;",
            "  *rva = address - image_base;",
            "  return 1;",
            "}",
            "",
            "static stage_b_step_result run_baseline_cluster(",
            "    stage_b_runtime *runtime, stage_b_machine_state *state) {",
            f"  uint32_t current = UINT32_C(0x{int(manifest.cluster['entry_rva']):08x});",
            "  uint32_t step, indirect_rva;",
            "  stage_b_step_result result = { STAGE_B_UNIMPLEMENTED, current, 0U };",
            "  for (step = 0U; step < 4096U; ++step) {",
            "    result = stage_b_interpreter_step(runtime, state, current);",
            "    if ((result.kind == STAGE_B_FALLTHROUGH ||",
            "         result.kind == STAGE_B_JUMP || result.kind == STAGE_B_BRANCH) &&",
            "        cluster_contains_rva(result.target_rva)) {",
            "      current = result.target_rva;",
            "      continue;",
            "    }",
            "    if (result.kind == STAGE_B_INDIRECT_JUMP &&",
            "        (cluster_contains_rva(result.value) ||",
            "         (image_address_to_rva(result.value, &indirect_rva) &&",
            "          cluster_contains_rva(indirect_rva)))) {",
            "      current = cluster_contains_rva(result.value) ? result.value : indirect_rva;",
            "      continue;",
            "    }",
            "    return result;",
            "  }",
            "  return (stage_b_step_result){ STAGE_B_UNIMPLEMENTED, current, 0U };",
            "}",
            "",
            "static void emit_observation(char side, uint32_t case_index, stage_b_step_result result,",
            "    const stage_b_machine_state *state, harness_context *context,",
            "    const harness_view *views, uint32_t view_count) {",
            "  uint32_t index, offset;",
            "  printf(\"O %c %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u\\n\",",
            "      side, case_index, (unsigned)result.kind, result.target_rva, result.value,",
            "      state->eax, state->ebx, state->ecx, state->edx, state->esi, state->edi, state->ebp, state->esp,",
            "      state->cf, state->zf, state->sf, state->of, state->pf, state->df, state->original_rva);",
            "  for (index = 0U; index < view_count; ++index) {",
            "    printf(\"M %c %u %u %u \", side, case_index, index, views[index].address);",
            "    for (offset = 0U; offset < views[index].width; ++offset) {",
            "      int cell = find_byte(context, views[index].address + offset);",
            "      printf(\"%02x\", cell < 0 ? 0U : context->bytes[cell].value);",
            "    }",
            "    putchar('\\n');",
            "  }",
            "  printf(\"W %c %u %u %u\\n\", side, case_index, context->write_count,",
            "      context->write_overflow);",
            "  for (index = 0U; index < context->write_count && index < 512U; ++index)",
            "    printf(\"B %c %u %u %u\\n\", side, case_index,",
            "        context->writes[index].address, context->writes[index].value);",
            "  printf(\"E %c %u %u %u\\n\", side, case_index, context->event_count,",
            "      context->event_overflow);",
            f"  for (index = 0U; index < context->event_count && index < {event_capacity}U; ++index) {{",
            "    uint32_t argument_index, stack_index;",
            "    harness_event *event = &context->events[index];",
            "    printf(\"T %c %u %u %s %u %u %u %u %u %u %u %u %u\",",
            "        side, case_index, index, event->identity, event->kind,",
            "        event->instruction_rva, event->call_index, event->target_rva,",
            "        event->return_rva, event->ordinal, event->has_ordinal,",
            "        event->argument_count, event->stack_input_count);",
            "    for (argument_index = 0U; argument_index < 8U; ++argument_index)",
            "      printf(\" %u\", event->registers[argument_index]);",
            "    for (argument_index = 0U; argument_index < 6U; ++argument_index)",
            "      printf(\" %u\", event->flags[argument_index]);",
            "    for (argument_index = 0U;",
            "         argument_index < event->argument_count;",
            "         ++argument_index)",
            "      printf(\" %u\", event->arguments[argument_index]);",
            "    for (stack_index = 0U; stack_index < event->stack_input_count; ++stack_index)",
            "      printf(\" %u %u %u\", event->stack_inputs[stack_index].offset,",
            "          event->stack_inputs[stack_index].width,",
            "          event->stack_inputs[stack_index].value);",
            "    putchar('\\n');",
            "  }",
            "}",
            "",
            "static void run_case(uint32_t case_index, const stage_b_machine_state *initial,",
            "    const harness_initial_byte *bytes, uint32_t byte_count,",
            "    const harness_view *views, uint32_t view_count,",
            "    const harness_response *responses, uint32_t response_count) {",
            "  stage_b_machine_state baseline_state = *initial, replacement_state = *initial;",
            "  harness_context baseline_context, replacement_context;",
            "  stage_b_runtime baseline_runtime, replacement_runtime;",
            "  stage_b_step_result baseline_result, replacement_result;",
            "  initialize_context(&baseline_context, bytes, byte_count, responses, response_count);",
            "  initialize_context(&replacement_context, bytes, byte_count, responses, response_count);",
            "  memset(&baseline_runtime, 0, sizeof(baseline_runtime));",
            "  baseline_runtime.context = &baseline_context;",
            "  baseline_runtime.read = harness_read;",
            "  baseline_runtime.write = harness_write;",
            "  baseline_runtime.atomic_compare_exchange = harness_atomic_compare_exchange_impl;",
            "  baseline_runtime.atomic_exchange = harness_atomic_exchange_impl;",
            "  baseline_runtime.external_call_fallback = harness_external;",
            "#ifdef STAGE_B_MACHINE_STATE_HAS_X87",
            "  baseline_runtime.execute_typed_x87_operation = harness_execute_typed_x87_operation;",
            "#endif",
            "  replacement_runtime = baseline_runtime;",
            "  replacement_runtime.context = &replacement_context;",
            "  baseline_result = run_baseline_cluster(&baseline_runtime, &baseline_state);",
            f"  replacement_result = {symbol}(&replacement_runtime, &replacement_state);",
            *fallback_lines,
            "  emit_observation('b', case_index, baseline_result, &baseline_state, &baseline_context, views, view_count);",
            "  emit_observation('r', case_index, replacement_result, &replacement_state, &replacement_context, views, view_count);",
            "}",
            "",
            "int main(void) {",
            *initializers,
            *invocations,
            "  return 0;",
            "}",
            "",
        ]
    )


def _regional_call_stack_observations(
    cases: Mapping[str, Any],
) -> tuple[tuple[int, tuple[tuple[int, int], ...]], ...]:
    """Validate explicit call-state observations requested by a checked profile."""

    rows = _array(
        cases.get("call_stack_observations", []),
        "regional call stack observations",
    )
    result = []
    seen_events: set[int] = set()
    for index, raw in enumerate(rows):
        row = _object(raw, f"regional call stack observation {index}")
        if set(row) != {"event_index", "slots"}:
            raise StageAInputError(
                "regional call stack observation has unexpected fields"
            )
        event_index = int(row["event_index"])
        if not 0 <= event_index < 16 or event_index in seen_events:
            raise StageAInputError(
                "regional call stack observation event index is invalid or duplicate"
            )
        seen_events.add(event_index)
        slots = []
        seen_slots: set[tuple[int, int]] = set()
        for slot_index, raw_slot in enumerate(
            _array(row.get("slots"), f"regional call stack slots {index}")
        ):
            slot = _object(
                raw_slot,
                f"regional call stack observation {index} slot {slot_index}",
            )
            if set(slot) != {"offset", "width"}:
                raise StageAInputError(
                    "regional call stack observation slot has unexpected fields"
                )
            offset = int(slot["offset"])
            width = int(slot["width"])
            identity = (offset, width)
            if (
                not 0 <= offset <= 0xFFFFFFFF
                or width not in {1, 2, 4}
                or identity in seen_slots
            ):
                raise StageAInputError(
                    "regional call stack observation slot is invalid or duplicate"
                )
            seen_slots.add(identity)
            slots.append(identity)
        if not slots:
            raise StageAInputError(
                "regional call stack observation must contain at least one slot"
            )
        result.append((event_index, tuple(slots)))
    return tuple(sorted(result))


def _parse_regional_observations(
    *, manifest: RegionReplacementManifest, cases: Mapping[str, Any], text: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    parsed: dict[tuple[str, int], dict[str, Any]] = {}
    for raw in text.splitlines():
        fields = raw.split()
        if not fields:
            continue
        if len(fields) < 4 or fields[1] not in {"b", "r"}:
            raise StageAInputError(f"malformed regional harness observation: {raw!r}")
        key = (fields[1], int(fields[2]))
        observed = parsed.setdefault(
            key,
            {
                "memory": {},
                "write_summary": None,
                "writes": {},
                "event_summary": None,
                "events": {},
            },
        )
        if fields[0] == "O":
            if len(fields) != 21:
                raise StageAInputError(f"malformed state observation: {raw!r}")
            values = [int(value) for value in fields[3:]]
            observed["result"] = values[:3]
            state_values = values[3:]
            observed["state"] = dict(zip(_REGISTERS + _FLAGS + ("original_rva",), state_values, strict=True))
        elif fields[0] == "M":
            if len(fields) != 6:
                raise StageAInputError(f"malformed memory observation: {raw!r}")
            observed["memory"][int(fields[3])] = {
                "base": int(fields[4]), "after": fields[5]
            }
        elif fields[0] == "W":
            if len(fields) != 5:
                raise StageAInputError(f"malformed write summary: {raw!r}")
            observed["write_summary"] = {
                "count": int(fields[3]),
                "overflow": int(fields[4]),
            }
        elif fields[0] == "B":
            if len(fields) != 5:
                raise StageAInputError(f"malformed guest-write record: {raw!r}")
            address = int(fields[3])
            if address in observed["writes"]:
                raise StageAInputError(f"duplicate guest-write record: {raw!r}")
            observed["writes"][address] = int(fields[4])
        elif fields[0] == "E":
            if len(fields) != 5:
                raise StageAInputError(f"malformed event summary: {raw!r}")
            observed["event_summary"] = {
                "count": int(fields[3]),
                "overflow": int(fields[4]),
            }
        elif fields[0] == "T":
            if len(fields) < 28:
                raise StageAInputError(f"malformed event trace record: {raw!r}")
            event_index = int(fields[3])
            argument_count = int(fields[12])
            stack_input_count = int(fields[13])
            expected_fields = 28 + argument_count + 3 * stack_input_count
            if len(fields) != expected_fields or event_index in observed["events"]:
                raise StageAInputError(f"malformed event trace record: {raw!r}")
            state_start = 14
            arguments_start = state_start + len(_REGISTERS) + len(_FLAGS)
            stack_start = arguments_start + argument_count
            state_values = [int(value) for value in fields[state_start:arguments_start]]
            stack_values = [int(value) for value in fields[stack_start:]]
            observed["events"][event_index] = {
                "identity": fields[4],
                "arguments": [
                    int(value)
                    for value in fields[arguments_start:stack_start]
                ],
                "machine_call": {
                    "kind": int(fields[5]),
                    "instruction_rva": int(fields[6]),
                    "call_index": int(fields[7]),
                    "target_rva": int(fields[8]),
                    "return_rva": int(fields[9]),
                    "ordinal": int(fields[10]),
                    "has_ordinal": bool(int(fields[11])),
                    "registers": dict(
                        zip(_REGISTERS, state_values[: len(_REGISTERS)], strict=True)
                    ),
                    "flags": dict(
                        zip(_FLAGS, state_values[len(_REGISTERS) :], strict=True)
                    ),
                    "stack_inputs": [
                        {
                            "offset": stack_values[index],
                            "width": stack_values[index + 1],
                            "value": stack_values[index + 2],
                        }
                        for index in range(0, len(stack_values), 3)
                    ],
                },
            }
        else:
            raise StageAInputError(f"unknown regional observation record: {raw!r}")

    artifacts = {}
    manifest_payload = manifest.to_payload()
    controls = manifest_payload["expectations"]["control"]
    memory_views = manifest_payload["memory_views"]
    external_expected = manifest_payload["expectations"]["external_events"]
    for side in ("b", "r"):
        output_cases = []
        for index, raw_case in enumerate(_array(cases.get("cases"), "reconstruction cases")):
            case = _object(raw_case, f"reconstruction case {index}")
            observed = parsed.get((side, index))
            if (
                observed is None
                or "result" not in observed
                or observed.get("write_summary") is None
                or observed.get("event_summary") is None
            ):
                raise StageAInputError(f"regional harness omitted {side} case {index}")
            result_kind, target_rva, result_value = observed["result"]
            kind = {
                0: "fallthrough", 1: "jump", 2: "branch", 3: "return",
                4: "indirect_jump", 9: "external_jump",
            }.get(result_kind)
            if kind is None:
                raise StageAInputError(
                    f"regional harness case {index} produced fault/control kind {result_kind}"
                )
            control = next((item for item in controls if item["kind"] == kind), None)
            if control is None:
                raise StageAInputError(f"regional harness produced undeclared control kind {kind}")
            target_unit = None
            state = observed["state"]
            live_inputs = [
                {"id": item["id"], "value": _case_live_value(case, item)}
                for item in manifest_payload["live_state"]["inputs"]
            ]
            live_outputs = [
                {"id": item["id"], "value": state[item["location"]]}
                for item in manifest_payload["live_state"]["outputs"]
            ]
            observed_memory = []
            for view_index, view in enumerate(memory_views):
                base = int(observed["memory"][view_index]["base"])
                before = _initial_memory_hex(case, base, int(view["byte_length"]))
                observed_memory.append(
                    {
                        "id": view["id"], "base": base, "before": before,
                        "after": observed["memory"][view_index]["after"],
                    }
                )
            write_summary = observed["write_summary"]
            write_records = observed["writes"]
            if (
                int(write_summary["overflow"]) != 0
                or int(write_summary["count"]) != len(write_records)
            ):
                raise StageAInputError(
                    "regional harness emitted an incomplete guest-write set: "
                    f"count={write_summary['count']} "
                    f"overflow={write_summary['overflow']} "
                    f"records={len(write_records)}"
                )
            guest_memory_writes = [
                {"address": address, "after": f"{write_records[address]:02x}"}
                for address in sorted(write_records)
            ]
            event_summary = observed["event_summary"]
            event_records = observed["events"]
            external_events = []
            if (
                int(event_summary["overflow"]) != 0
                or int(event_summary["count"]) != len(event_records)
                or set(event_records) != set(range(len(event_records)))
            ):
                raise StageAInputError(
                    "regional harness emitted an incomplete external trace: "
                    f"count={event_summary['count']} overflow={event_summary['overflow']} "
                    f"records={sorted(event_records)} expected={len(external_expected)}"
                )
            has_checked_sites = all(
                "instruction_rva" in item and "return_rva" in item
                for item in external_expected
            )
            expected_by_site = (
                {
                    (
                        str(item["identity"]),
                        int(item["instruction_rva"]),
                        int(item["return_rva"]),
                    ): item
                    for item in external_expected
                }
                if has_checked_sites
                else {}
            )
            if has_checked_sites and len(expected_by_site) != len(external_expected):
                raise StageAInputError("regional manifest has ambiguous external-event sites")
            if not has_checked_sites and len(event_records) > len(external_expected):
                raise StageAInputError(
                    "legacy regional manifest cannot describe a repeated external event"
                )
            for event_index in range(len(event_records)):
                event_record = event_records[event_index]
                machine_call = _object(
                    event_record.get("machine_call"), "observed machine call"
                )
                site_key = (
                    str(event_record["identity"]),
                    int(machine_call["instruction_rva"]),
                    int(machine_call["return_rva"]),
                )
                expected = (
                    expected_by_site.get(site_key)
                    if has_checked_sites
                    else external_expected[event_index]
                )
                if expected is None:
                    raise StageAInputError(
                        "regional harness external trace uses an undeclared call site: "
                        f"event={event_index} identity={event_record['identity']} "
                        f"instruction_rva=0x{int(machine_call['instruction_rva']):08x}"
                    )
                if not has_checked_sites and event_record["identity"] != expected["identity"]:
                    raise StageAInputError(
                        "legacy regional harness external trace is not a declared prefix: "
                        f"event={event_index} observed={event_record['identity']} "
                        f"expected={expected['identity']}"
                    )
                external_events.append(
                    {
                        "id": expected["id"],
                        "kind": expected["kind"],
                        "identity": event_record["identity"],
                        "arguments": event_record["arguments"],
                        "machine_call": event_record["machine_call"],
                        "memory_reads": [], "result": {}, "memory_writes": [],
                        "callbacks": [],
                    }
                )
            output_cases.append(
                {
                    "id": case["id"],
                    "entry_unit_id": manifest.cluster["entry_unit_id"],
                    "live_inputs": live_inputs,
                    "live_outputs": live_outputs,
                    "memory_views": observed_memory,
                    "guest_memory_writes": guest_memory_writes,
                    "control": {
                        "id": control["id"], "kind": kind,
                        "target_unit_id": target_unit,
                        "target_rva": target_rva or None,
                        "value": result_value,
                    },
                    "fault": None,
                    "external_events": external_events,
                }
            )
        artifacts[side] = {
            "format": "stage-b-region-observations-v1",
            "manifest_sha256": manifest.manifest_sha256,
            "cases": output_cases,
        }
    return artifacts["b"], artifacts["r"]


def _evaluate_base_expression(expression: str, registers: Mapping[str, Any]) -> int:
    if expression.startswith("{"):
        try:
            semantic_expression = json.loads(expression)
        except json.JSONDecodeError as error:
            raise StageAInputError(
                f"regional harness has malformed semantic memory base {expression!r}"
            ) from error
        return _evaluate_semantic_address(semantic_expression, registers)
    if expression.startswith("input.") and " + " not in expression:
        return int(registers[expression.removeprefix("input.")]) & 0xFFFFFFFF
    if re.fullmatch(r"0x[0-9a-fA-F]{1,8}", expression):
        return int(expression, 16)
    match = re.fullmatch(r"input\.([a-z]{3}) \+ 0x([0-9a-fA-F]{1,8})", expression)
    if match:
        return (int(registers[match.group(1)]) + int(match.group(2), 16)) & 0xFFFFFFFF
    raise StageAInputError(f"regional harness cannot evaluate memory base {expression!r}")


def _case_live_value(case: Mapping[str, Any], live: Mapping[str, Any]) -> int:
    inventory = case["flags"] if live["kind"] == "flag" else case["registers"]
    return int(inventory[live["location"]])


def _initial_memory_hex(case: Mapping[str, Any], base: int, width: int) -> str:
    memory: dict[int, int] = {}
    for raw in case["memory"]:
        address = int(raw["address"])
        for offset, value in enumerate(bytes.fromhex(str(raw["bytes"]))):
            memory[address + offset] = value
    return bytes(memory.get(base + offset, 0) for offset in range(width)).hex()


def _case(name: str, registers: Mapping[str, int], flags: Mapping[str, int], memory: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    return {
        "id": f"case:{name}",
        "registers": dict(sorted(registers.items())),
        "flags": dict(sorted(flags.items())),
        "memory": sorted((dict(item) for item in memory), key=lambda item: item["address"]),
        "external_response_seed": _canonical_sha256({"case": name})[:16],
    }


def _workspace_readme(cluster: Mapping[str, Any], portable: Mapping[str, int], adapter: Mapping[str, int]) -> str:
    return (
        "# Reconstruction workspace\n\n"
        f"Cluster: `{cluster['id']}` at RVA `0x{int(cluster['entry_rva']):08x}`.\n\n"
        f"Edit the portable logic in `{portable['path']}` lines {portable['line_start']}-"
        f"{portable['line_end']}. The machine adapter on lines {adapter['line_start']}-"
        f"{adapter['line_end']} of `{adapter['path']}` is generated boundary code.\n\n"
        "After editing, rebind the source hash, run the candidate-only regional check, "
        "and promote only a qualified validation report. The original binary is never "
        "executed by this workspace.\n"
    )


def _source_edit_map(generated: Path, edited: Path) -> dict[str, Any]:
    before = generated.read_text(encoding="ascii").splitlines()
    after = edited.read_text(encoding="ascii").splitlines()
    changed = []
    for tag, before_start, before_end, after_start, after_end in SequenceMatcher(
        a=before, b=after, autojunk=False
    ).get_opcodes():
        if tag == "equal":
            continue
        changed.append(
            {
                "path": f"{edited.parent.name}/{edited.name}",
                "change": tag,
                "line_start": after_start + 1,
                "line_end": max(after_start + 1, after_end),
                "generated_line_start": before_start + 1,
                "generated_line_end": max(before_start + 1, before_end),
                "generated": before[before_start:before_end],
                "edited": after[after_start:after_end],
            }
        )
    payload = {
        "format": "stage-b-reconstruction-edit-map-v1",
        "generated_source_sha256": sha256_file(generated),
        "edited_source_sha256": sha256_file(edited),
        "changed_ranges": changed,
        "counts": {"changed_ranges": len(changed)},
    }
    return payload


def _load_workspace(root: Path) -> Mapping[str, Any]:
    payload = _read_object(root / "workspace.json", "reconstruction workspace")
    _require_format(payload, COMPONENT_BACKEND_WORKSPACE_FORMAT, "reconstruction workspace")
    return payload


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


def _control_contract(unit: Mapping[str, Any], by_rva: Mapping[int, Mapping[str, Any]]) -> list[dict[str, Any]]:
    outcome = unit.get("semantics", {}).get("outcome", {})
    kind = str(outcome.get("kind") or unit.get("control", {}).get("kind"))
    targets = []
    for field in ("target_rva", "true_target_rva", "false_target_rva"):
        value = outcome.get(field)
        if isinstance(value, int) and value not in targets:
            targets.append(value)
    if kind == "branch":
        return [
            {
                "kind": "branch",
                "target_rvas": sorted(targets),
                "target_unit_ids": sorted(str(by_rva[target]["id"]) for target in targets if target in by_rva),
            }
        ]
    return [
        {
            "kind": kind,
            "target_rvas": sorted(targets),
            "target_unit_ids": sorted(str(by_rva[target]["id"]) for target in targets if target in by_rva),
        }
    ]


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


def _live_value(item: Mapping[str, Any], evidence_id: str) -> dict[str, Any]:
    name = str(item["name"])
    kind = str(item["kind"])
    return {
        "id": f"live:{kind}:{name}",
        "kind": kind,
        "location": name,
        "width_bits": 1 if kind == "flag" else 32,
        "encoding": "bit" if kind == "flag" else "uint32",
        "evidence_ids": [evidence_id],
    }


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


def _const_expr(value: Any, context: str) -> int:
    if not isinstance(value, dict) or value.get("op") != "const" or not isinstance(value.get("value"), int):
        raise StageAInputError(f"{context} is not a constant expression")
    return int(value["value"])


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


def _slug(value: str) -> str:
    result = re.sub(r"[^A-Za-z0-9]+", "-", value).strip("-").lower()
    return result or "region"


def _c_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


__all__ = [
    "RECONSTRUCTION_PLAN_FORMAT",
    "RECONSTRUCTION_REGISTRY_FORMAT",
    "RECONSTRUCTION_STATUS_FORMAT",
    "COMPONENT_BACKEND_WORKSPACE_FORMAT",
    "ReconstructionWorkspace",
    "build_reconstruction_regional_kernel",
    "check_component_backend_workspace",
    "create_component_backend_workspace",
    "promote_component_backend_workspaces",
    "rebind_component_backend_workspace",
    "run_component_backend_check",
    "write_reconstruction_plan",
    "write_reconstruction_status",
]

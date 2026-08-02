"""Qualified semantic-component workspaces and hybrid activation.

This layer binds editable portable C to a validated semantic component.  It
reuses the regional override ABI, but sampled regional checks cannot authorize
activation by themselves: source evidence, generated-adapter integrity, the
component boundary, and candidate-only integration must all be current.
"""

from __future__ import annotations

import copy
import json
import re
import shutil
import subprocess
from hashlib import sha256
from pathlib import Path
from typing import Any, Mapping, Sequence

from .artifact_formats import (
    COMPONENT_EVIDENCE_FORMAT,
    COMPONENT_QUALIFICATION_FORMAT,
    COMPONENT_REFINEMENT_FORMAT,
    COMPONENT_REGISTRY_FORMAT,
    COMPONENT_WORKSPACE_FORMAT,
    COMPONENT_SLICE_FORMAT,
    COMPONENT_SLICE_PACKAGE_FORMAT,
    RECONSTRUCTION_PLAN_FORMAT,
    SEMANTIC_COMPONENT_CATALOG_FORMAT,
)
from .reconstruction_workspace import (
    _load_machine_ir,
    create_reconstruction_workspace,
    promote_reconstruction_workspaces,
    rebind_reconstruction_workspace,
)
from .stage_binary import StageAInputError
from .util import sha256_file, write_json


_PROOF_PROFILES = {
    "compare_branch_v1",
    "constant_service_call_v1",
    "store_then_zero_call_v1",
    "atomic_compare_exchange_v1",
    "finite_dispatch_v1",
    "alias_sensitive_word_update_v1",
}


def create_component_slice_package(
    *,
    catalog: Path,
    plan: Path,
    machine_ir: Path,
    component_ids: Sequence[str],
    out_dir: Path,
) -> dict[str, Any]:
    """Reduce large immutable Stage B inputs to one checked slice per component.

    This is a performance artifact, not proof authority.  It is generated once
    per catalog/plan/machine-IR tuple and binds every retained record to those
    full inputs by hash.
    """

    requested = [str(value) for value in component_ids]
    if not requested or len(set(requested)) != len(requested):
        raise StageAInputError("component slice package requires unique component IDs")
    catalog_path = Path(catalog)
    plan_path = Path(plan)
    catalog_payload = _read_object(catalog_path, "semantic component catalog")
    plan_payload = _read_object(plan_path, "reconstruction plan")
    _require_format(
        catalog_payload, SEMANTIC_COMPONENT_CATALOG_FORMAT, "semantic component catalog"
    )
    _require_format(plan_payload, RECONSTRUCTION_PLAN_FORMAT, "reconstruction plan")
    if catalog_payload.get("definition_status") != "valid":
        raise StageAInputError("semantic component catalog definitions are not valid")
    _check_catalog_bindings(catalog_payload, plan_payload, machine_ir)
    package = _load_machine_ir(Path(machine_ir))
    by_id = {str(unit["id"]): unit for unit in package.units}
    output = Path(out_dir)
    slices_dir = output / "slices"
    slices_dir.mkdir(parents=True, exist_ok=True)
    entries: list[dict[str, Any]] = []
    for component_id in sorted(requested):
        component = _select_component(catalog_payload, component_id)
        if component.get("definition_status") != "valid":
            raise StageAInputError(f"semantic component is not valid: {component_id}")
        if component.get("kind") == "aggregate":
            raise StageAInputError("aggregate components cannot be sliced for implementation")
        entry_rva = _component_entry_rva(component)
        cluster = _select_plan_cluster(plan_payload, component, entry_rva)
        required_ids = sorted(
            {
                *(str(value) for value in cluster.get("unit_ids", [])),
                str(cluster.get("entry_unit_id")),
                *(
                    str(value)
                    for value in component.get("membership", {}).get(
                        "resolved_unit_ids", []
                    )
                ),
            }
        )
        missing = [unit_id for unit_id in required_ids if unit_id not in by_id]
        if missing:
            raise StageAInputError(
                f"component {component_id} slice references unknown machine units: {missing}"
            )
        slice_core = {
            "format": COMPONENT_SLICE_FORMAT,
            "status": "checked",
            "executes_original_binary": False,
            "component_id": component_id,
            "bindings": {
                "catalog_artifact_sha256": sha256_file(catalog_path),
                "reconstruction_plan_artifact_sha256": sha256_file(plan_path),
                "reconstruction_plan_sha256": plan_payload["plan_sha256"],
                "machine_ir_sha256": package.machine_ir_sha256,
            },
            "component": copy.deepcopy(component),
            "cluster": copy.deepcopy(cluster),
            "units": [copy.deepcopy(by_id[unit_id]) for unit_id in required_ids],
            "catalog_coverage": copy.deepcopy(catalog_payload.get("coverage", {})),
            "counts": {
                "machine_units": len(required_ids),
                "full_machine_units": len(package.units),
            },
        }
        slice_payload = {
            **slice_core,
            "slice_sha256": _canonical_sha256(slice_core),
        }
        relative = Path("slices") / f"{_slug(component_id)}.json"
        path = output / relative
        write_json(path, slice_payload)
        entries.append(
            {
                "component_id": component_id,
                "path": relative.as_posix(),
                "sha256": sha256_file(path),
                "slice_sha256": slice_payload["slice_sha256"],
                "machine_units": len(required_ids),
            }
        )
    package_core = {
        "format": COMPONENT_SLICE_PACKAGE_FORMAT,
        "status": "checked",
        "executes_original_binary": False,
        "bindings": {
            "catalog_artifact_sha256": sha256_file(catalog_path),
            "reconstruction_plan_artifact_sha256": sha256_file(plan_path),
            "reconstruction_plan_sha256": plan_payload["plan_sha256"],
            "machine_ir_sha256": package.machine_ir_sha256,
        },
        "entries": entries,
        "counts": {
            "components": len(entries),
            "full_machine_units": len(package.units),
        },
    }
    package_payload = {
        **package_core,
        "package_sha256": _canonical_sha256(package_core),
    }
    write_json(output / "component-slice-package.json", package_payload)
    return package_payload


def create_component_workspace(
    *,
    catalog: Path | None,
    plan: Path | None,
    machine_ir: Path | None,
    interpreter_package: Path,
    component_id: str,
    proof_profile: str,
    out_dir: Path,
    component_slice: Path | None = None,
) -> dict[str, Any]:
    """Create an editable workspace bound to one validated component."""

    if proof_profile not in _PROOF_PROFILES:
        raise StageAInputError(f"unsupported component proof profile: {proof_profile}")
    slice_payload: Mapping[str, Any] | None = None
    if component_slice is None:
        if catalog is None or plan is None or machine_ir is None:
            raise StageAInputError(
                "component workspace requires either a component slice or all full inputs"
            )
        catalog_path = Path(catalog)
        catalog_payload = _read_object(catalog_path, "semantic component catalog")
        _require_format(
            catalog_payload, SEMANTIC_COMPONENT_CATALOG_FORMAT, "semantic component catalog"
        )
        if catalog_payload.get("definition_status") != "valid":
            raise StageAInputError("semantic component catalog definitions are not valid")
        component = _select_component(catalog_payload, component_id)
        plan_path = Path(plan)
        plan_payload = _read_object(plan_path, "reconstruction plan")
        _require_format(plan_payload, RECONSTRUCTION_PLAN_FORMAT, "reconstruction plan")
        _check_catalog_bindings(catalog_payload, plan_payload, machine_ir)
        catalog_artifact_sha256 = sha256_file(catalog_path)
        machine_ir_sha256 = str(catalog_payload["bindings"]["machine_ir_sha256"])
        entry_rva = _component_entry_rva(component)
        cluster = _select_plan_cluster(plan_payload, component, entry_rva)
    else:
        if catalog is not None or plan is not None or machine_ir is not None:
            raise StageAInputError(
                "component slices cannot be combined with full component inputs"
            )
        slice_payload = _load_component_slice(Path(component_slice), component_id)
        component = _object(slice_payload.get("component"), "sliced component")
        cluster = _object(slice_payload.get("cluster"), "sliced reconstruction cluster")
        bindings = _object(slice_payload.get("bindings"), "component slice bindings")
        plan_payload = {"plan_sha256": bindings["reconstruction_plan_sha256"]}
        catalog_payload = {
            "coverage": copy.deepcopy(slice_payload.get("catalog_coverage", {}))
        }
        catalog_artifact_sha256 = str(bindings["catalog_artifact_sha256"])
        machine_ir_sha256 = str(bindings["machine_ir_sha256"])
        entry_rva = _component_entry_rva(component)
    if component.get("definition_status") != "valid":
        raise StageAInputError(f"semantic component is not valid: {component_id}")
    if component.get("kind") == "aggregate":
        raise StageAInputError("aggregate components cannot be implemented directly")
    _validate_profile_shape(proof_profile, component, cluster)

    out_dir = Path(out_dir)
    create_reconstruction_workspace(
        plan=(Path(plan) if slice_payload is None and plan is not None else None),
        machine_ir=(Path(machine_ir) if slice_payload is None and machine_ir is not None else None),
        interpreter_package=Path(interpreter_package),
        out_dir=out_dir,
        cluster_id=str(cluster["id"]),
        adapter_unit_ids=component["membership"]["resolved_unit_ids"],
        prepared_slice=(
            None
            if slice_payload is None
            else {
                "plan_sha256": plan_payload["plan_sha256"],
                "machine_ir_sha256": machine_ir_sha256,
                "cluster": cluster,
                "units": slice_payload["units"],
            }
        ),
    )
    backend_workspace = _read_object(out_dir / "workspace.json", "backend workspace")
    portable_symbol = _namespace_portable_function(
        root=out_dir,
        backend_workspace=backend_workspace,
        entry_rva=entry_rva,
    )
    rebind_reconstruction_workspace(workspace=out_dir)
    backend_workspace = _read_object(out_dir / "workspace.json", "backend workspace")
    adapter_path = out_dir / backend_workspace["files"]["machine_adapter_source"]
    portable_path = out_dir / backend_workspace["files"]["portable_source"]
    header_path = out_dir / backend_workspace["files"]["portable_header"]
    adapter_reference = out_dir / "contract" / "generated-machine-adapter.c"
    shutil.copyfile(adapter_path, adapter_reference)

    boundary = _object(component.get("machine_boundary"), "component machine boundary")
    refinement_core = {
        "format": COMPONENT_REFINEMENT_FORMAT,
        "status": "checked",
        "executes_original_binary": False,
        "component": {
            "id": component_id,
            "sha256": component["component_sha256"],
            "entry_rva": entry_rva,
            "unit_ids": component["membership"]["resolved_unit_ids"],
        },
        "bindings": {
            "catalog_sha256": catalog_artifact_sha256,
            "machine_ir_sha256": machine_ir_sha256,
            "reconstruction_plan_sha256": plan_payload["plan_sha256"],
            "backend_workspace_sha256": backend_workspace["workspace_sha256"],
            "portable_source_sha256": sha256_file(portable_path),
            "portable_header_sha256": sha256_file(header_path),
            "generated_adapter_sha256": sha256_file(adapter_path),
        },
        "proof_profile": proof_profile,
        "portable_symbol": portable_symbol,
        "logical_interface": copy.deepcopy(component["logical_interface"]),
        "reachability": copy.deepcopy(component["reachability"]),
        "global_coverage_counts": copy.deepcopy(
            catalog_payload.get("coverage", {}).get("counts", {})
        ),
        "machine_projection": {
            "status": "checked",
            "entry_rvas": [item["rva"] for item in boundary.get("entries", [])],
            "external_exit_count": len(boundary.get("exits", [])),
            "call_closure": copy.deepcopy(boundary.get("call_closure", {})),
            "internal_call_frames": copy.deepcopy(
                boundary.get("effects", {}).get("internal_call_frames", [])
            ),
            "control_and_faults_preserved_by": "generated_machine_adapter_v1",
        },
        "adapter_effect_plan": {
            "ordering": "machine_boundary_order",
            "memory": copy.deepcopy(boundary.get("effects", {}).get("memory", [])),
            "external_events": copy.deepcopy(
                boundary.get("effects", {}).get("external_events", [])
            ),
            "internal_call_frames": copy.deepcopy(
                boundary.get("effects", {}).get("internal_call_frames", [])
            ),
            "exits": copy.deepcopy(boundary.get("exits", [])),
            "faults": copy.deepcopy(boundary.get("effects", {}).get("faults", [])),
        },
        "frame_rule": {
            "status": "checked",
            "policy": "all state outside declared adapter effects must be preserved",
        },
    }
    refinement = {
        **refinement_core,
        "refinement_sha256": _canonical_sha256(refinement_core),
    }
    refinement_path = out_dir / "contract" / "component-refinement.json"
    write_json(refinement_path, refinement)

    component_workspace_core = {
        "format": COMPONENT_WORKSPACE_FORMAT,
        "status": "editable",
        "executes_original_binary": False,
        "component_id": component_id,
        "proof_profile": proof_profile,
        "bindings": {
            "component_sha256": component["component_sha256"],
            "refinement_sha256": refinement["refinement_sha256"],
            "backend_workspace_sha256": backend_workspace["workspace_sha256"],
            "portable_source_sha256": sha256_file(portable_path),
            "generated_adapter_sha256": sha256_file(adapter_path),
        },
        "files": {
            "backend_workspace": "workspace.json",
            "refinement": "contract/component-refinement.json",
            "portable_source": backend_workspace["files"]["portable_source"],
            "portable_header": backend_workspace["files"]["portable_header"],
            "machine_adapter_source": backend_workspace["files"]["machine_adapter_source"],
            "generated_adapter_reference": "contract/generated-machine-adapter.c",
            "replacement_manifest": backend_workspace["files"]["replacement_manifest"],
        },
        "activation": {
            "status": "blocked_pending_qualification",
            "required_artifact": COMPONENT_QUALIFICATION_FORMAT,
        },
    }
    component_workspace = {
        **component_workspace_core,
        "workspace_sha256": _canonical_sha256(component_workspace_core),
    }
    write_json(out_dir / "component-workspace.json", component_workspace)
    return component_workspace


def rebind_component_workspace(*, workspace: Path) -> dict[str, Any]:
    """Refresh all source bindings after an intentional portable-C edit."""

    root = Path(workspace)
    component_workspace = _load_component_workspace(root)
    refinement_path = root / component_workspace["files"]["refinement"]
    refinement = _read_object(refinement_path, "component refinement")
    portable = root / component_workspace["files"]["portable_source"]
    _enforce_portable_symbol(portable, str(refinement["portable_symbol"]))
    backend = rebind_reconstruction_workspace(workspace=root)
    header = root / component_workspace["files"]["portable_header"]
    adapter = root / component_workspace["files"]["machine_adapter_source"]
    backend_workspace = _read_object(root / "workspace.json", "backend workspace")
    refinement["bindings"].update(
        {
            "backend_workspace_sha256": backend_workspace["workspace_sha256"],
            "portable_source_sha256": sha256_file(portable),
            "portable_header_sha256": sha256_file(header),
            "generated_adapter_sha256": sha256_file(adapter),
        }
    )
    refinement.pop("refinement_sha256", None)
    refinement["refinement_sha256"] = _canonical_sha256(refinement)
    write_json(refinement_path, refinement)
    component_workspace["bindings"].update(
        {
            "refinement_sha256": refinement["refinement_sha256"],
            "backend_workspace_sha256": backend_workspace["workspace_sha256"],
            "portable_source_sha256": sha256_file(portable),
            "generated_adapter_sha256": sha256_file(adapter),
            "replacement_manifest_sha256": backend.manifest_sha256,
        }
    )
    component_workspace["activation"]["status"] = "blocked_pending_qualification"
    component_workspace.pop("workspace_sha256", None)
    component_workspace["workspace_sha256"] = _canonical_sha256(component_workspace)
    write_json(root / "component-workspace.json", component_workspace)
    return component_workspace


def run_component_source_check(
    *, workspace: Path, cbmc: str, out: Path, timeout_seconds: int = 120
) -> dict[str, Any]:
    """Use CBMC to check the editable portable implementation against its contract."""

    root = Path(workspace)
    metadata = _load_component_workspace(root)
    refinement = _load_bound_refinement(root, metadata)
    source = root / metadata["files"]["portable_source"]
    header = root / metadata["files"]["portable_header"]
    harness = _render_cbmc_harness(
        profile=str(metadata["proof_profile"]), refinement=refinement
    )
    harness_path = Path(out).parent / "component-cbmc-harness.c"
    harness_path.parent.mkdir(parents=True, exist_ok=True)
    harness_path.write_text(harness, encoding="ascii")
    command = [
        cbmc,
        str(source),
        str(harness_path),
        "-I",
        str(header.parent),
        "--function",
        "main",
        "--bounds-check",
        "--pointer-check",
        "--div-by-zero-check",
        "--signed-overflow-check",
        "--undefined-shift-check",
        "--unwinding-assertions",
        "--unwind",
        "6",
        "--json-ui",
    ]
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
        timed_out = False
    except subprocess.TimeoutExpired as exc:
        completed = None
        timed_out = True
        stdout = exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode() if isinstance(exc.stderr, bytes) else (exc.stderr or "")
    if not timed_out:
        assert completed is not None
        stdout, stderr = completed.stdout, completed.stderr
    version = subprocess.run(
        [cbmc, "--version"], check=False, capture_output=True, text=True
    ).stdout.strip()
    violations = _cbmc_violations(stdout)
    if timed_out:
        status = "incomplete"
        reason = "cbmc_timeout"
    elif completed.returncode == 0 and not violations:
        status = "satisfied"
        reason = None
    elif violations:
        status = "violated"
        reason = "source_contract_counterexample"
    else:
        status = "incomplete"
        reason = "cbmc_failed_without_counterexample"
    payload_core = {
        "format": COMPONENT_EVIDENCE_FORMAT,
        "family": "source_behavior",
        "provider": "cbmc",
        "status": status,
        "executes_original_binary": False,
        "bindings": {
            "component_id": metadata["component_id"],
            "component_workspace_sha256": metadata["workspace_sha256"],
            "refinement_sha256": refinement["refinement_sha256"],
            "portable_source_sha256": sha256_file(source),
            "portable_header_sha256": sha256_file(header),
            "harness_sha256": sha256_file(harness_path),
        },
        "scope": {
            "kind": "universal_bounded_c_source",
            "proof_profile": metadata["proof_profile"],
            "unwind": 6,
        },
        "tool": {"version": version, "arguments": command[3:]},
        "reason": reason,
        "counterexamples": violations,
        "diagnostics": {
            "returncode": None if timed_out else completed.returncode,
            "stderr": stderr[-4000:],
        },
    }
    payload = {**payload_core, "evidence_sha256": _canonical_sha256(payload_core)}
    write_json(Path(out), payload)
    (Path(out).parent / "cbmc-report.json").write_text(stdout, encoding="utf-8")
    return payload


def qualify_component(
    *, workspace: Path, source_evidence: Path, out: Path
) -> dict[str, Any]:
    """Close all evidence families required before hybrid activation."""

    root = Path(workspace)
    metadata = _load_component_workspace(root)
    refinement = _load_bound_refinement(root, metadata)
    evidence_path = Path(source_evidence)
    evidence = _read_object(evidence_path, "component source evidence")
    _require_format(evidence, COMPONENT_EVIDENCE_FORMAT, "component source evidence")
    adapter = root / metadata["files"]["machine_adapter_source"]
    adapter_reference = root / metadata["files"]["generated_adapter_reference"]
    portable = root / metadata["files"]["portable_source"]
    integration_path = root / "validation-report.json"
    integration = (
        _read_object(integration_path, "component integration report")
        if integration_path.is_file()
        else None
    )
    checks = [
        _check("source_behavior", evidence.get("status") == "satisfied", evidence.get("status")),
        _check(
            "source_binding",
            evidence.get("bindings", {}).get("portable_source_sha256") == sha256_file(portable),
            "stale" if evidence.get("bindings", {}).get("portable_source_sha256") != sha256_file(portable) else "current",
        ),
        _check(
            "refinement_binding",
            evidence.get("bindings", {}).get("refinement_sha256") == refinement["refinement_sha256"],
            "stale" if evidence.get("bindings", {}).get("refinement_sha256") != refinement["refinement_sha256"] else "current",
        ),
        _check(
            "generated_adapter",
            adapter.is_file()
            and adapter_reference.is_file()
            and sha256_file(adapter) == sha256_file(adapter_reference)
            and sha256_file(adapter) == refinement["bindings"]["generated_adapter_sha256"],
            "byte_exact" if adapter.is_file() and adapter_reference.is_file() and sha256_file(adapter) == sha256_file(adapter_reference) else "modified",
        ),
        _check(
            "candidate_integration",
            integration is not None and integration.get("status") == "qualified",
            None if integration is None else integration.get("status"),
        ),
        _check(
            "machine_projection",
            refinement.get("machine_projection", {}).get("status") == "checked",
            refinement.get("machine_projection", {}).get("status"),
        ),
        _check(
            "call_closure",
            _call_closure_acceptable(refinement),
            _call_closure_status(refinement),
        ),
    ]
    if integration is not None:
        manifest_sha = _read_object(
            root / metadata["files"]["replacement_manifest"],
            "region replacement manifest",
        ).get("manifest_sha256")
        checks.append(
            _check(
                "integration_binding",
                integration.get("bindings", {}).get("replacement_manifest_sha256")
                == manifest_sha,
                "current"
                if integration.get("bindings", {}).get("replacement_manifest_sha256")
                == manifest_sha
                else "stale",
            )
        )
    failed = [item for item in checks if item["status"] != "satisfied"]
    status = "qualified" if not failed else (
        "violated" if any(item["observed"] == "violated" for item in failed) else "incomplete"
    )
    payload_core = {
        "format": COMPONENT_QUALIFICATION_FORMAT,
        "status": status,
        "executes_original_binary": False,
        "component_id": metadata["component_id"],
        "bindings": {
            "component_workspace_sha256": metadata["workspace_sha256"],
            "refinement_sha256": refinement["refinement_sha256"],
            "source_evidence_sha256": sha256_file(evidence_path),
            "replacement_manifest_sha256": _read_object(
                root / metadata["files"]["replacement_manifest"],
                "region replacement manifest",
            )["manifest_sha256"],
        },
        "checks": checks,
        "counts": {
            "required_families": len(checks),
            "satisfied": len(checks) - len(failed),
            "incomplete_or_violated": len(failed),
        },
        "activation": {
            "authorized": not failed,
            "backend": "stage_b_region_override_v2",
        },
    }
    payload = {
        **payload_core,
        "qualification_sha256": _canonical_sha256(payload_core),
    }
    write_json(Path(out), payload)
    return payload


def promote_qualified_components(
    *, workspaces: Sequence[Path], qualifications: Sequence[Path], out_dir: Path
) -> dict[str, Any]:
    """Lower qualified components into the existing regional override backend."""

    if len(workspaces) != len(qualifications) or not workspaces:
        raise StageAInputError("promotion requires paired component workspaces and qualifications")
    qualified: list[tuple[Path, Mapping[str, Any]]] = []
    seen: set[str] = set()
    for workspace, qualification in zip(workspaces, qualifications, strict=True):
        root = Path(workspace)
        metadata = _load_component_workspace(root)
        payload = _read_object(Path(qualification), "component qualification")
        _require_format(payload, COMPONENT_QUALIFICATION_FORMAT, "component qualification")
        if payload.get("status") != "qualified" or not payload.get("activation", {}).get("authorized"):
            raise StageAInputError(f"component is not qualified: {metadata['component_id']}")
        if payload.get("component_id") != metadata["component_id"]:
            raise StageAInputError("component qualification/workspace identity mismatch")
        if payload.get("bindings", {}).get("component_workspace_sha256") != metadata["workspace_sha256"]:
            raise StageAInputError(f"component qualification is stale: {metadata['component_id']}")
        if metadata["component_id"] in seen:
            raise StageAInputError(f"duplicate component activation: {metadata['component_id']}")
        seen.add(str(metadata["component_id"]))
        qualified.append((root, payload))

    out_dir = Path(out_dir)
    backend = promote_reconstruction_workspaces(
        workspaces=[item[0] for item in qualified], out_dir=out_dir
    )
    entries = []
    qualified_unit_ids: set[str] = set()
    global_counts: Mapping[str, Any] | None = None
    for root, qualification in sorted(qualified, key=lambda item: str(item[1]["component_id"])):
        metadata = _load_component_workspace(root)
        refinement = _load_bound_refinement(root, metadata)
        qualified_unit_ids.update(str(value) for value in refinement["component"]["unit_ids"])
        observed_counts = refinement.get("global_coverage_counts", {})
        if global_counts is None:
            global_counts = observed_counts
        elif observed_counts != global_counts:
            raise StageAInputError("qualified components disagree on global coverage counts")
        entries.append(
            {
                "component_id": metadata["component_id"],
                "proof_profile": metadata["proof_profile"],
                "qualification_sha256": qualification["qualification_sha256"],
                "workspace_sha256": metadata["workspace_sha256"],
                "entry_rva": _read_object(
                    root / metadata["files"]["replacement_manifest"],
                    "region replacement manifest",
                )["cluster"]["entry_rva"],
            }
        )
    machine_units = None if global_counts is None else global_counts.get("machine_units")
    remaining_units = (
        None
        if not isinstance(machine_units, int)
        else int(machine_units) - len(qualified_unit_ids)
    )
    payload_core = {
        "format": COMPONENT_REGISTRY_FORMAT,
        "status": "qualified",
        "executes_original_binary": False,
        "activation_policy": "qualified_components_only",
        "entries": entries,
        "override_table": copy.deepcopy(backend["override_table"]),
        "backend_registry": {
            "path": "reconstruction-registry.json",
            "sha256": sha256_file(out_dir / "reconstruction-registry.json"),
        },
        "counts": {"components": len(entries), "replacements": len(entries)},
        "whole_program_status": (
            "qualified" if remaining_units == 0 else "incomplete"
        ),
        "coverage": {
            "qualified_unit_ids": sorted(qualified_unit_ids),
            "qualified_units": len(qualified_unit_ids),
            "machine_units": machine_units,
            "remaining_units": remaining_units,
            "interpretation": (
                "component qualification authorizes only listed override entries; "
                "it does not claim whole-program reconstruction"
            ),
        },
    }
    payload = {**payload_core, "registry_sha256": _canonical_sha256(payload_core)}
    write_json(out_dir / "component-registry.json", payload)
    return payload


def _render_cbmc_harness(*, profile: str, refinement: Mapping[str, Any]) -> str:
    symbol = str(refinement.get("portable_symbol") or "")
    if not symbol:
        raise StageAInputError("component refinement omits its portable symbol")
    if profile == "compare_branch_v1":
        body = """
int main(void) {
  uint32_t left = nondet_u32();
  uint32_t right = nondet_u32();
  reconstructed_compare_result result = __FUNCTION__(left, right);
  __CPROVER_assert(result.difference == left - right, "difference");
  __CPROVER_assert(result.equal == (left == right), "equality");
  return 0;
}
""".replace("__FUNCTION__", symbol)
    elif profile == "constant_service_call_v1":
        identity, argument = _service_contract(refinement)
        method = _slug(identity)
        body = f"""
static uint32_t calls;
static uint32_t observed;
static int answer;
static int service(void *context, uint32_t argument) {{
  (void)context; calls++; observed = argument; return answer;
}}
int main(void) {{
  reconstructed_services services = {{ 0, service }};
  answer = nondet_int();
  int result = {symbol}(&services);
  __CPROVER_assert(calls == 1U, "one {method} call");
  __CPROVER_assert(observed == UINT32_C({argument}), "service argument");
  __CPROVER_assert(result == answer, "service result");
  return 0;
}}
"""
    elif profile == "store_then_zero_call_v1":
        body = """
int main(void) {
  uint32_t shared = nondet_u32();
  reconstructed_initialization result = __FUNCTION__(shared);
  __CPROVER_assert(result.stored_value == shared, "stored word");
  __CPROVER_assert(result.result == 0U, "zero helper result");
  return 0;
}
""".replace("__FUNCTION__", symbol)
    elif profile == "atomic_compare_exchange_v1":
        body = """
static uint32_t parity8(uint32_t value) {
  value ^= value >> 4; value &= 15U;
  return (UINT32_C(0x9669) >> value) & 1U;
}
int main(void) {
  reconstructed_region_inputs input;
  reconstructed_region_outputs output = { 0U };
  input.atomic_00_observed = nondet_u32();
  input.atomic_00_exchanged = nondet_u32() & 1U;
  uint32_t difference = 0U - input.atomic_00_observed;
  __CPROVER_assert(__FUNCTION__(&input, &output), "implemented");
  __CPROVER_assert(output.register_eax == input.atomic_00_observed, "eax");
  __CPROVER_assert(output.flag_cf == (0U < input.atomic_00_observed), "cf");
  __CPROVER_assert(output.flag_of == ((input.atomic_00_observed & difference & UINT32_C(0x80000000)) != 0U), "of");
  __CPROVER_assert(output.flag_pf == parity8(difference), "pf");
  __CPROVER_assert(output.flag_sf == (difference >> 31), "sf");
  __CPROVER_assert(output.flag_zf == input.atomic_00_exchanged, "zf");
  __CPROVER_assert(output.control_kind == RECONSTRUCTED_BRANCH, "branch");
  __CPROVER_assert(output.target_rva == (input.atomic_00_exchanged ? UINT32_C(0x105c) : UINT32_C(0x1038)), "target");
  return 0;
}
""".replace("__FUNCTION__", symbol)
    elif profile == "finite_dispatch_v1":
        body = """
int main(void) {
  reconstructed_region_inputs input;
  reconstructed_region_outputs output = { 0U };
  input.register_eax = nondet_u32();
  input.memory_view_00_p4330740 = nondet_u32();
  uint32_t selector = input.register_eax & UINT32_C(0xff);
  bool implemented = __FUNCTION__(&input, &output);
  __CPROVER_assert(implemented == (selector < 36U), "selector domain");
  if (implemented) {
    __CPROVER_assert(output.register_edx == selector, "selector output");
    __CPROVER_assert(output.control_kind == RECONSTRUCTED_INDIRECT_JUMP, "indirect control");
    __CPROVER_assert(output.value == input.memory_view_00_p4330740, "target word");
  }
  return 0;
}
""".replace("__FUNCTION__", symbol)
    elif profile == "alias_sensitive_word_update_v1":
        body = _alias_sensitive_harness(symbol)
    else:
        raise StageAInputError(f"unsupported component proof profile: {profile}")
    return (
        '#include "implementation.h"\n'
        "#include <stdint.h>\n\n"
        "extern uint32_t nondet_u32(void);\n"
        "extern int nondet_int(void);\n"
        + body.lstrip()
    )


def _alias_sensitive_harness(symbol: str) -> str:
    return r'''
static uint32_t parity8(uint32_t value) {
  value ^= value >> 4; value &= 15U;
  return (UINT32_C(0x9669) >> value) & 1U;
}
static uint32_t overlay(uint32_t address, uint32_t initial,
                        uint32_t a8, uint32_t v8,
                        uint32_t a4, uint32_t v4) {
  uint32_t result = initial;
  for (uint32_t index = 0U; index < 4U; ++index) {
    uint32_t byte_address = address + index;
    uint32_t byte_value = (initial >> (index * 8U)) & 255U;
    if (byte_address - a8 < 4U)
      byte_value = (v8 >> ((byte_address - a8) * 8U)) & 255U;
    if (byte_address - a4 < 4U)
      byte_value = (v4 >> ((byte_address - a4) * 8U)) & 255U;
    result = (result & ~(255U << (index * 8U))) | (byte_value << (index * 8U));
  }
  return result;
}
int main(void) {
  reconstructed_region_inputs i;
  reconstructed_region_outputs o = { 0U };
  i.register_ebx = nondet_u32(); i.register_esp = nondet_u32();
  i.memory_view_00_p12 = nondet_u32(); i.memory_view_00_p16 = nondet_u32();
  i.memory_view_00_p20 = nondet_u32(); i.memory_view_00_p76 = nondet_u32();
  i.memory_view_00_p80 = nondet_u32(); i.memory_view_00_p84 = nondet_u32();
  i.memory_view_00_p88 = nondet_u32(); i.memory_view_01_p4 = nondet_u32();
  i.memory_view_01_p8 = nondet_u32();
  uint32_t a8 = i.register_ebx + 8U, v8 = i.memory_view_01_p8 + i.memory_view_00_p12;
  uint32_t a4 = i.register_ebx + 4U, v4 = i.memory_view_01_p4 | UINT32_C(0x1c0);
  uint32_t adjusted = i.register_esp + 76U;
  __CPROVER_assert(__FUNCTION__(&i, &o), "implemented");
  __CPROVER_assert(o.write_memory_view_01_p8 && o.memory_view_01_p8 == v8, "word 8 write");
  __CPROVER_assert(o.write_memory_view_01_p4 && o.memory_view_01_p4 == v4, "word 4 write");
  __CPROVER_assert(o.register_eax == overlay(i.register_esp + 16U, i.memory_view_00_p16, a8, v8, a4, v4), "eax restore");
  __CPROVER_assert(o.register_edx == overlay(i.register_esp + 20U, i.memory_view_00_p20, a8, v8, a4, v4), "edx restore");
  __CPROVER_assert(o.register_ebx == overlay(i.register_esp + 76U, i.memory_view_00_p76, a8, v8, a4, v4), "ebx restore");
  __CPROVER_assert(o.register_esi == overlay(i.register_esp + 80U, i.memory_view_00_p80, a8, v8, a4, v4), "esi restore");
  __CPROVER_assert(o.register_edi == overlay(i.register_esp + 84U, i.memory_view_00_p84, a8, v8, a4, v4), "edi restore");
  __CPROVER_assert(o.register_ebp == overlay(i.register_esp + 88U, i.memory_view_00_p88, a8, v8, a4, v4), "ebp restore");
  __CPROVER_assert(o.register_ecx == i.register_ebx && o.register_esp == i.register_esp + 92U, "frame outputs");
  __CPROVER_assert(o.flag_cf == (adjusted < i.register_esp), "cf");
  __CPROVER_assert(o.flag_of == ((~(i.register_esp ^ 76U) & (i.register_esp ^ adjusted) & UINT32_C(0x80000000)) != 0U), "of");
  __CPROVER_assert(o.flag_pf == parity8(adjusted) && o.flag_sf == (adjusted >> 31) && o.flag_zf == (adjusted == 0U), "arithmetic flags");
  __CPROVER_assert(o.control_kind == RECONSTRUCTED_JUMP && o.target_rva == UINT32_C(0xbf30), "control");
  return 0;
}
'''.replace("__FUNCTION__", symbol)


def _validate_profile_shape(
    profile: str, component: Mapping[str, Any], cluster: Mapping[str, Any]
) -> None:
    template = str(cluster.get("template") or "manual_contract")
    required_template = {
        "compare_branch_v1": "compare_branch",
        "constant_service_call_v1": "constant_external_call",
        "store_then_zero_call_v1": "store_then_zero_call",
        "atomic_compare_exchange_v1": "manual_contract",
        "finite_dispatch_v1": "manual_contract",
        "alias_sensitive_word_update_v1": "manual_contract",
    }[profile]
    if template != required_template:
        raise StageAInputError(
            f"proof profile {profile} requires template {required_template}, observed {template}"
        )
    boundary = component.get("machine_boundary", {})
    if profile == "store_then_zero_call_v1" and (
        boundary.get("call_closure", {}).get("status") != "complete"
        or len(boundary.get("internal_calls", [])) != 1
        or len(boundary.get("internal_returns", [])) != 1
    ):
        raise StageAInputError("store/zero component requires one closed internal call frame")
    if profile == "constant_service_call_v1" and not boundary.get("effects", {}).get("external_events"):
        raise StageAInputError("service component has no external event")
    if profile == "finite_dispatch_v1" and not any(
        str(item.get("kind", "")).startswith("indirect")
        for item in boundary.get("exits", [])
    ):
        raise StageAInputError("finite-dispatch component has no indirect exit")


def _namespace_portable_function(
    *, root: Path, backend_workspace: Mapping[str, Any], entry_rva: int
) -> str:
    """Give every portable helper a stable link-visible component namespace."""

    files = backend_workspace.get("files", {})
    paths = [
        root / str(files["portable_source"]),
        root / str(files["portable_header"]),
        root / str(files["machine_adapter_source"]),
    ]
    header = paths[1].read_text(encoding="ascii")
    candidates = (
        "compare_values",
        "run_service_operation",
        "initialize_word",
        "reconstruct_region",
    )
    matches = [name for name in candidates if re.search(rf"\b{name}\b", header)]
    if len(matches) != 1:
        raise StageAInputError(
            f"component adapter has {len(matches)} portable entry symbols: {matches}"
        )
    original = matches[0]
    replacement = f"component_{entry_rva:08x}_{original}"
    pattern = re.compile(rf"\b{re.escape(original)}\b")
    for path in paths:
        text = path.read_text(encoding="ascii")
        replaced, count = pattern.subn(replacement, text)
        if count == 0:
            raise StageAInputError(f"portable symbol {original} is absent from {path}")
        path.write_text(replaced, encoding="ascii")
    return replacement


def _enforce_portable_symbol(source: Path, expected: str) -> None:
    text = source.read_text(encoding="ascii")
    if re.search(rf"\b{re.escape(expected)}\b", text):
        return
    suffixes = (
        "compare_values",
        "run_service_operation",
        "initialize_word",
        "reconstruct_region",
    )
    matches = [name for name in suffixes if re.search(rf"\b{name}\b", text)]
    if len(matches) != 1:
        raise StageAInputError(
            f"portable source cannot be rebound to {expected}: found {matches}"
        )
    replaced, count = re.subn(rf"\b{re.escape(matches[0])}\b", expected, text)
    if count == 0:
        raise StageAInputError(f"portable source omits expected entry {expected}")
    source.write_text(replaced, encoding="ascii")


def _component_entry_rva(component: Mapping[str, Any]) -> int:
    entries = component.get("machine_boundary", {}).get("entries", [])
    external = [item for item in entries if item.get("kind") != "internal_call"]
    selected = external or entries
    rvas = sorted({int(item["rva"]) for item in selected if isinstance(item.get("rva"), int)})
    if len(rvas) != 1:
        raise StageAInputError(
            f"component {component.get('id')} requires exactly one activation entry, observed {rvas}"
        )
    return rvas[0]


def _select_plan_cluster(
    plan: Mapping[str, Any], component: Mapping[str, Any], entry_rva: int
) -> Mapping[str, Any]:
    clusters = [item for item in plan.get("clusters", []) if isinstance(item, Mapping)]
    declared = component.get("membership", {}).get("cluster_ids", [])
    matches = [item for item in clusters if item.get("id") in declared]
    if not matches:
        matches = [item for item in clusters if item.get("entry_rva") == entry_rva]
    if len(matches) != 1:
        raise StageAInputError(
            f"component {component.get('id')} has {len(matches)} reconstruction clusters"
        )
    return matches[0]


def _check_catalog_bindings(
    catalog: Mapping[str, Any], plan: Mapping[str, Any], machine_ir: Path
) -> None:
    if catalog.get("bindings", {}).get("reconstruction_plan_sha256") != plan.get("plan_sha256"):
        raise StageAInputError("semantic component catalog is stale for reconstruction plan")
    machine_path = Path(machine_ir)
    if machine_path.is_dir():
        machine_path = machine_path / "machine-ir.jsonl"
    if sha256_file(machine_path) != catalog.get("bindings", {}).get("machine_ir_sha256"):
        raise StageAInputError("semantic component catalog is stale for machine IR")


def _service_contract(refinement: Mapping[str, Any]) -> tuple[str, int]:
    events = refinement.get("adapter_effect_plan", {}).get("external_events", [])
    if len(events) != 1:
        raise StageAInputError("service proof profile requires exactly one external event")
    event = events[0].get("event", events[0])
    identity = str(event.get("symbol") or event.get("identity", {}).get("symbol") or "service")
    stack_inputs = event.get("stack_inputs", [])
    if len(stack_inputs) != 1 or stack_inputs[0].get("value", {}).get("op") != "const":
        raise StageAInputError("service proof profile requires one constant argument")
    return identity, int(stack_inputs[0]["value"]["value"])


def _call_closure_status(refinement: Mapping[str, Any]) -> str:
    frames = refinement.get("adapter_effect_plan", {}).get("internal_call_frames", [])
    if not frames:
        return "not_applicable"
    return str(
        refinement.get("machine_projection", {})
        .get("call_closure", {})
        .get("status", "incomplete")
    )


def _call_closure_acceptable(refinement: Mapping[str, Any]) -> bool:
    frames = refinement.get("adapter_effect_plan", {}).get("internal_call_frames", [])
    return not frames or _call_closure_status(refinement) == "complete"


def _cbmc_violations(stdout: str) -> list[dict[str, Any]]:
    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError:
        return []
    violations = []
    rows = payload if isinstance(payload, list) else [payload]
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        for result in row.get("result", []):
            if not isinstance(result, Mapping) or result.get("status") != "FAILURE":
                continue
            location = result.get("sourceLocation", {})
            violations.append(
                {
                    "property": result.get("property"),
                    "description": result.get("description"),
                    "location": {
                        "file": location.get("file"),
                        "line": location.get("line"),
                        "function": location.get("function"),
                    },
                }
            )
    return violations


def _check(family: str, satisfied: bool, observed: Any) -> dict[str, Any]:
    return {
        "family": family,
        "status": (
            "satisfied"
            if satisfied
            else ("violated" if observed == "violated" else "incomplete")
        ),
        "observed": observed,
    }


def _select_component(catalog: Mapping[str, Any], component_id: str) -> Mapping[str, Any]:
    matches = [
        item
        for item in catalog.get("components", [])
        if isinstance(item, Mapping) and item.get("id") == component_id
    ]
    if len(matches) != 1:
        raise StageAInputError(
            f"semantic component catalog has {len(matches)} matches for {component_id}"
        )
    return matches[0]


def _load_component_workspace(root: Path) -> dict[str, Any]:
    payload = _read_object(root / "component-workspace.json", "component workspace")
    _require_format(payload, COMPONENT_WORKSPACE_FORMAT, "component workspace")
    expected = payload.get("workspace_sha256")
    copy_payload = copy.deepcopy(payload)
    copy_payload.pop("workspace_sha256", None)
    if expected != _canonical_sha256(copy_payload):
        raise StageAInputError("component workspace self-hash is stale")
    return payload


def _load_component_slice(path: Path, component_id: str) -> dict[str, Any]:
    payload = _read_object(path, "component slice")
    _require_format(payload, COMPONENT_SLICE_FORMAT, "component slice")
    if payload.get("status") != "checked" or payload.get("executes_original_binary") is not False:
        raise StageAInputError("component slice is not a checked static artifact")
    if payload.get("component_id") != component_id:
        raise StageAInputError("component slice ID does not match requested component")
    expected = payload.get("slice_sha256")
    copy_payload = copy.deepcopy(payload)
    copy_payload.pop("slice_sha256", None)
    if expected != _canonical_sha256(copy_payload):
        raise StageAInputError("component slice self-hash is stale")
    component = _object(payload.get("component"), "sliced component")
    cluster = _object(payload.get("cluster"), "sliced reconstruction cluster")
    units = payload.get("units")
    if not isinstance(units, list) or not units:
        raise StageAInputError("component slice has no machine units")
    available = {
        str(item.get("id"))
        for item in units
        if isinstance(item, Mapping) and isinstance(item.get("id"), str)
    }
    required = {
        *(str(value) for value in cluster.get("unit_ids", [])),
        str(cluster.get("entry_unit_id")),
        *(
            str(value)
            for value in component.get("membership", {}).get(
                "resolved_unit_ids", []
            )
        ),
    }
    missing = sorted(required - available)
    if missing:
        raise StageAInputError(
            f"component slice omits required machine units: {missing}"
        )
    return payload


def _load_bound_refinement(
    root: Path, metadata: Mapping[str, Any]
) -> dict[str, Any]:
    payload = _read_object(root / metadata["files"]["refinement"], "component refinement")
    _require_format(payload, COMPONENT_REFINEMENT_FORMAT, "component refinement")
    expected = payload.get("refinement_sha256")
    copy_payload = copy.deepcopy(payload)
    copy_payload.pop("refinement_sha256", None)
    if expected != _canonical_sha256(copy_payload):
        raise StageAInputError("component refinement self-hash is stale")
    if expected != metadata.get("bindings", {}).get("refinement_sha256"):
        raise StageAInputError("component workspace/refinement binding is stale")
    return payload


def _read_object(path: Path, description: str) -> dict[str, Any]:
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise StageAInputError(f"cannot read {description}: {exc}") from exc
    if not isinstance(payload, dict):
        raise StageAInputError(f"{description} must be a JSON object")
    return payload


def _object(value: Any, description: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise StageAInputError(f"{description} must be an object")
    return value


def _require_format(payload: Mapping[str, Any], expected: str, description: str) -> None:
    if payload.get("format") != expected:
        raise StageAInputError(f"unsupported {description} format")


def _slug(value: str) -> str:
    return "".join(character.lower() if character.isalnum() else "_" for character in value)


def _canonical_sha256(payload: Mapping[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return sha256(encoded).hexdigest()


__all__ = [
    "create_component_slice_package",
    "create_component_workspace",
    "promote_qualified_components",
    "qualify_component",
    "rebind_component_workspace",
    "run_component_source_check",
]

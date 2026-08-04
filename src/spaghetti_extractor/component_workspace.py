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
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any, Mapping, Sequence

from .artifact_formats import (
    COMPONENT_EVIDENCE_FORMAT,
    COMPONENT_INTERFACE_REFINEMENT_FORMAT,
    COMPONENT_QUALIFICATION_FORMAT,
    COMPONENT_REFINEMENT_FORMAT,
    COMPONENT_REGISTRY_FORMAT,
    COMPONENT_WORKSPACE_FORMAT,
    COMPONENT_SLICE_FORMAT,
    COMPONENT_SLICE_PACKAGE_FORMAT,
    FINITE_COMPONENT_CONTRACT_FORMAT,
    RECONSTRUCTION_PLAN_FORMAT,
    SEMANTIC_COMPONENT_CATALOG_FORMAT,
)
from .bounded_component_contract import (
    BOUNDED_STRING_CONTRACT_FORMAT,
    derive_bounded_string_length_contract,
    validate_bounded_string_contract,
)
from .component_profile import (
    ComponentProfileContext,
    PreparedComponentProfile,
    load_component_profile,
)
from .component_backend import (
    _load_machine_ir,
    create_component_backend_workspace,
    promote_component_backend_workspaces,
    rebind_component_backend_workspace,
)
from .finite_component_contract import (
    derive_finite_scalar_contract,
    derive_finite_static_string_contract,
)
from .linked_library_contracts import (
    LinkedLibraryContractError,
    validate_linked_island_manifest,
)
from .stage_binary import StageAInputError
from .util import sha256_file, write_json


_PROOF_PROFILES = {
    "compare_branch_v1",
    "constant_compare_branch_v1",
    "constant_service_call_v1",
    "store_then_zero_call_v1",
    "atomic_compare_exchange_v1",
    "finite_dispatch_v1",
    "alias_sensitive_word_update_v1",
    "bounded_range_rotation_v1",
    "bounded_string_length_v1",
    "finite_acyclic_scalar_v1",
    "finite_acyclic_static_string_lookup_v1",
}

_BOUNDED_RANGE_ROTATION_WORDS = 6
_BOUNDED_STRING_LENGTH_BYTES = 16
_BOUNDED_PAIRWISE_BYTE_COMPARE_BYTES = 16
_WORD_MASK = 0xFFFFFFFF


@dataclass(frozen=True)
class _CheckedComponentDependency:
    root: Path
    declaration: Mapping[str, Any]
    workspace: Mapping[str, Any]
    refinement: Mapping[str, Any]
    qualification: Mapping[str, Any]

    def proof_binding(self) -> dict[str, Any]:
        contract = _component_proof_contract_from_refinement(self.refinement)
        activation = _object(
            self.qualification.get("activation"),
            "component dependency activation",
        )
        core = {
            "target_component_id": str(self.declaration["target_component_id"]),
            "target_rva": int(self.declaration["target_rva"]),
            "target_unit_id": str(self.declaration["target_unit_id"]),
            "selection_dependency_sha256": str(
                self.declaration["dependency_sha256"]
            ),
            "callsites": copy.deepcopy(
                _array(
                    self.declaration.get("callsites"),
                    "selected dependency callsites",
                )
            ),
            "qualification_sha256": str(
                self.qualification["qualification_sha256"]
            ),
            "refinement_sha256": str(self.refinement["refinement_sha256"]),
            "portable_symbol": str(self.refinement["portable_symbol"]),
            "portable_source_sha256": str(
                self.refinement["bindings"]["portable_source_sha256"]
            ),
            "activation": {
                "authorized": bool(activation.get("authorized")),
                "kind": str(
                    _object(activation.get("domain"), "dependency activation domain").get(
                        "kind"
                    )
                ),
            },
            "external_trace": copy.deepcopy(
                _object(
                    self.refinement.get("component_call_dependencies"),
                    "component dependency call plan",
                ).get("external_trace", [])
            ),
            "component_contract": copy.deepcopy(contract),
            **(
                {
                    "finite_component_contract": copy.deepcopy(
                        contract["payload"]
                    )
                }
                if contract["field"] == "finite_component_contract"
                else {}
            ),
        }
        return {**core, "binding_sha256": _canonical_sha256(core)}


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
                # A slice is local to one component. Binding the component's
                # self-hash keeps unrelated catalog additions out of its
                # content identity while preserving exact local provenance.
                "catalog_artifact_sha256": component["component_sha256"],
                "catalog_binding_kind": "component_self_hash",
                "reconstruction_plan_artifact_sha256": sha256_file(plan_path),
                "reconstruction_plan_sha256": plan_payload["plan_sha256"],
                "machine_ir_sha256": package.machine_ir_sha256,
            },
            "component": copy.deepcopy(component),
            "cluster": copy.deepcopy(cluster),
            "units": [copy.deepcopy(by_id[unit_id]) for unit_id in required_ids],
            "machine_ir_manifest": {
                "format": package.manifest.get("format"),
                "binary": copy.deepcopy(package.manifest.get("binary")),
            },
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
    interface_refinement: Path,
    component_slice: Path | None = None,
    static_image: Path | None = None,
    component_dependencies: Sequence[Path] = (),
) -> dict[str, Any]:
    """Create an editable workspace bound to one validated component."""

    profile_implementation = load_component_profile(proof_profile)
    if proof_profile not in _PROOF_PROFILES and profile_implementation is None:
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
        machine_ir_manifest = _load_machine_ir(Path(machine_ir)).manifest
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
        catalog_payload = {"coverage": {}}
        catalog_artifact_sha256 = str(bindings["catalog_artifact_sha256"])
        machine_ir_sha256 = str(bindings["machine_ir_sha256"])
        machine_ir_manifest = _object(
            slice_payload.get("machine_ir_manifest"),
            "component slice machine IR manifest",
        )
        entry_rva = _component_entry_rva(component)
    if component.get("definition_status") != "valid":
        raise StageAInputError(f"semantic component is not valid: {component_id}")
    if component.get("kind") == "aggregate":
        raise StageAInputError("aggregate components cannot be implemented directly")
    checked_dependencies = _load_checked_component_dependencies(
        component=component,
        dependency_roots=component_dependencies,
    )
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    dependency_bindings = _materialize_component_dependency_evidence(
        root=out_dir,
        dependencies=checked_dependencies,
        materialize=False,
    )
    if profile_implementation is None:
        _validate_profile_shape(
            proof_profile,
            component,
            cluster,
            component_dependencies=dependency_bindings,
        )
    checked_interface = _load_checked_interface_refinement(
        Path(interface_refinement),
        component=component,
        machine_ir_sha256=machine_ir_sha256,
    )
    execution_cluster = cluster
    execution_units: Sequence[Mapping[str, Any]] | None = None
    component_unit_id_list = [
        str(unit_id)
        for unit_id in component["membership"]["resolved_unit_ids"]
    ]
    component_unit_ids = set(component_unit_id_list)
    cluster_unit_ids = {
        str(unit_id) for unit_id in _array(cluster.get("unit_ids"), "cluster unit IDs")
    }
    prepared_profile: PreparedComponentProfile | None = None
    if profile_implementation is not None:
        if execution_units is None:
            if slice_payload is not None:
                execution_units = _select_machine_units(
                    _array(
                        slice_payload.get("units"), "component slice machine units"
                    ),
                    component_unit_id_list,
                    "component slice machine units",
                )
            else:
                package = _load_machine_ir(Path(machine_ir))
                execution_units = _select_machine_units(
                    package.units,
                    component_unit_id_list,
                    "machine IR units",
                )
        prepared_profile = profile_implementation.prepare(
            ComponentProfileContext(
                component=component,
                cluster=cluster,
                units=execution_units,
                machine_ir_manifest=machine_ir_manifest,
                machine_ir_sha256=machine_ir_sha256,
                interface_refinement=checked_interface,
                static_image=(
                    Path(static_image) if static_image is not None else None
                ),
                component_dependencies=dependency_bindings,
            )
        )
    # A profile is the authority for the component's regional comparison
    # projection even when discovery happened to produce the same unit set.
    # The raw cluster's inferred memory inventory can contain intermediate
    # symbolic addresses that are meaningful to analysis but are not stable
    # entry-state observables.
    if _needs_component_execution_cluster(
        has_profile=profile_implementation is not None,
        component_unit_ids=component_unit_ids,
        cluster_unit_ids=cluster_unit_ids,
        has_dependencies=bool(checked_dependencies),
    ):
        observable_memory: Sequence[Mapping[str, Any]] = ()
        if profile_implementation is not None:
            assert prepared_profile is not None
            observable_memory = profile_implementation.observable_memory(
                {
                    **checked_interface,
                    prepared_profile.contract_field: prepared_profile.contract,
                }
            )
        elif proof_profile == "bounded_range_rotation_v1":
            descriptor = _range_rotation_descriptor(
                _object(
                    checked_interface.get("logical_interface"),
                    "checked logical interface",
                )
            )
            observable_memory = descriptor["observable_memory"]
        if execution_units is None:
            if slice_payload is not None:
                execution_units = _select_machine_units(
                    _array(
                        slice_payload.get("units"), "component slice machine units"
                    ),
                    component_unit_id_list,
                    "component slice machine units",
                )
            else:
                package = _load_machine_ir(Path(machine_ir))
                execution_units = _select_machine_units(
                    package.units,
                    component_unit_id_list,
                    "machine IR units",
                )
        execution_cluster = _component_execution_cluster(
            selected_cluster=cluster,
            component=component,
            units=execution_units,
            observable_memory=observable_memory,
            component_dependencies=dependency_bindings,
        )

    finite_contract: Mapping[str, Any] | None = None
    bounded_string_contract: Mapping[str, Any] | None = None
    if proof_profile in {
        "finite_acyclic_scalar_v1",
        "finite_acyclic_static_string_lookup_v1",
    }:
        if (
            proof_profile == "finite_acyclic_static_string_lookup_v1"
            and static_image is None
        ):
            raise StageAInputError(
                "finite static-string profile requires the exact static PE image"
            )
        if execution_units is None:
            if slice_payload is not None:
                execution_units = _select_machine_units(
                    _array(
                        slice_payload.get("units"), "component slice machine units"
                    ),
                    component_unit_id_list,
                    "component slice machine units",
                )
            else:
                package = _load_machine_ir(Path(machine_ir))
                execution_units = _select_machine_units(
                    package.units,
                    component_unit_id_list,
                    "machine IR units",
                )
        finite_contract = (
            derive_finite_scalar_contract(
                component=component,
                units=execution_units,
                machine_ir_sha256=machine_ir_sha256,
            )
            if proof_profile == "finite_acyclic_scalar_v1"
            else derive_finite_static_string_contract(
                component=component,
                units=execution_units,
                machine_ir_manifest=machine_ir_manifest,
                machine_ir_sha256=machine_ir_sha256,
                static_image=Path(static_image),
            )
        )
    if proof_profile == "bounded_string_length_v1":
        if execution_units is None:
            if slice_payload is not None:
                execution_units = _select_machine_units(
                    _array(
                        slice_payload.get("units"), "component slice machine units"
                    ),
                    component_unit_id_list,
                    "component slice machine units",
                )
            else:
                package = _load_machine_ir(Path(machine_ir))
                execution_units = _select_machine_units(
                    package.units,
                    component_unit_id_list,
                    "machine IR units",
                )
        bounded_string_contract = derive_bounded_string_length_contract(
            component=component,
            units=execution_units,
            machine_ir_sha256=machine_ir_sha256,
            max_bytes=_BOUNDED_STRING_LENGTH_BYTES,
        )
    create_component_backend_workspace(
        plan=(
            Path(plan)
            if slice_payload is None
            and execution_units is None
            and plan is not None
            else None
        ),
        machine_ir=(
            Path(machine_ir)
            if slice_payload is None
            and execution_units is None
            and machine_ir is not None
            else None
        ),
        interpreter_package=Path(interpreter_package),
        out_dir=out_dir,
        cluster_id=str(execution_cluster["id"]),
        adapter_unit_ids=component["membership"]["resolved_unit_ids"],
        prepared_slice=(
            None
            if slice_payload is None and execution_units is None
            else {
                "plan_sha256": plan_payload["plan_sha256"],
                "machine_ir_sha256": machine_ir_sha256,
                "cluster": execution_cluster,
                "units": (
                    list(execution_units)
                    if execution_units is not None
                    else slice_payload["units"]
                ),
            }
        ),
    )
    materialized_dependency_bindings = _materialize_component_dependency_evidence(
        root=out_dir,
        dependencies=checked_dependencies,
        materialize=True,
    )
    if materialized_dependency_bindings != dependency_bindings:
        raise StageAInputError(
            "materialized component dependency evidence changed its proof binding"
        )
    backend_workspace = _read_object(out_dir / "workspace.json", "backend workspace")
    if profile_implementation is not None:
        assert prepared_profile is not None
        profile_implementation.install_sources(
            root=out_dir,
            backend_workspace=backend_workspace,
            entry_rva=entry_rva,
            prepared=prepared_profile,
        )
        profile_implementation.install_cases(
            root=out_dir,
            backend_workspace=backend_workspace,
            cluster=execution_cluster,
            prepared=prepared_profile,
        )
    else:
        _install_logical_profile_sources(
            root=out_dir,
            backend_workspace=backend_workspace,
            profile=proof_profile,
            interface_refinement=checked_interface,
            entry_rva=entry_rva,
            finite_contract=finite_contract,
            bounded_string_contract=bounded_string_contract,
            bounded_pairwise_contract=None,
        )
        _install_logical_profile_cases(
            root=out_dir,
            backend_workspace=backend_workspace,
            profile=proof_profile,
            cluster=execution_cluster,
            finite_contract=finite_contract,
            bounded_string_contract=bounded_string_contract,
            bounded_pairwise_contract=None,
        )
    _attach_component_dependency_support_sources(
        root=out_dir,
        backend_workspace=backend_workspace,
        dependency_bindings=materialized_dependency_bindings,
    )
    portable_symbol = _namespace_portable_function(
        root=out_dir,
        backend_workspace=backend_workspace,
        entry_rva=entry_rva,
        preferred_symbol=(
            prepared_profile.portable_symbol
            if prepared_profile is not None
            else None
        ),
    )
    rebind_component_backend_workspace(workspace=out_dir)
    backend_workspace = _read_object(out_dir / "workspace.json", "backend workspace")
    adapter_path = out_dir / backend_workspace["files"]["machine_adapter_source"]
    portable_path = out_dir / backend_workspace["files"]["portable_source"]
    header_path = out_dir / backend_workspace["files"]["portable_header"]
    adapter_reference = out_dir / "contract" / "generated-machine-adapter.c"
    shutil.copyfile(adapter_path, adapter_reference)
    interface_reference = out_dir / "contract" / "checked-logical-interface.json"
    write_json(interface_reference, checked_interface)
    finite_contract_reference = out_dir / "contract" / "finite-component-contract.json"
    if finite_contract is not None:
        write_json(finite_contract_reference, finite_contract)
    bounded_string_contract_reference = (
        out_dir / "contract" / "bounded-string-contract.json"
    )
    if bounded_string_contract is not None:
        write_json(bounded_string_contract_reference, bounded_string_contract)
    if prepared_profile is not None:
        write_json(
            out_dir / "contract" / prepared_profile.contract_filename,
            prepared_profile.contract,
        )

    component_call_plan = _normalized_component_call_plan(
        component=component,
        component_dependencies=dependency_bindings,
    )

    component_contract_descriptor: dict[str, Any] | None = None
    if prepared_profile is not None:
        component_contract_descriptor = {
            "field": prepared_profile.contract_field,
            "format": str(prepared_profile.contract["format"]),
            "contract_sha256": str(
                prepared_profile.contract["contract_sha256"]
            ),
        }
    elif finite_contract is not None:
        component_contract_descriptor = {
            "field": "finite_component_contract",
            "format": str(finite_contract["format"]),
            "contract_sha256": str(finite_contract["contract_sha256"]),
        }
    elif bounded_string_contract is not None:
        component_contract_descriptor = {
            "field": "bounded_string_contract",
            "format": str(bounded_string_contract["format"]),
            "contract_sha256": str(
                bounded_string_contract["contract_sha256"]
            ),
        }

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
            "logical_interface_artifact_sha256": sha256_file(interface_reference),
            "logical_interface_refinement_sha256": checked_interface[
                "refinement_sha256"
            ],
            **(
                {
                    "finite_component_contract_sha256": finite_contract[
                        "contract_sha256"
                    ]
                }
                if finite_contract is not None
                else {}
            ),
            **(
                {
                    "bounded_string_contract_sha256": bounded_string_contract[
                        "contract_sha256"
                    ]
                }
                if bounded_string_contract is not None
                else {}
            ),
            **(
                {
                    prepared_profile.contract_hash_binding: prepared_profile.contract[
                        "contract_sha256"
                    ]
                }
                if prepared_profile is not None
                else {}
            ),
        },
        "proof_profile": proof_profile,
        "portable_symbol": portable_symbol,
        **(
            {"component_contract": component_contract_descriptor}
            if component_contract_descriptor is not None
            else {}
        ),
        "logical_interface": copy.deepcopy(checked_interface["logical_interface"]),
        "logical_interface_refinement": {
            "status": "checked",
            "refinement_sha256": checked_interface["refinement_sha256"],
            "artifact": "checked-logical-interface.json",
        },
        **(
            {"finite_component_contract": copy.deepcopy(finite_contract)}
            if finite_contract is not None
            else {}
        ),
        **(
            {"bounded_string_contract": copy.deepcopy(bounded_string_contract)}
            if bounded_string_contract is not None
            else {}
        ),
        **(
            {
                prepared_profile.contract_field: copy.deepcopy(
                    prepared_profile.contract
                )
            }
            if prepared_profile is not None
            else {}
        ),
        "component_call_dependencies": copy.deepcopy(component_call_plan),
        "reachability": copy.deepcopy(component["reachability"]),
        "global_coverage_counts": copy.deepcopy(
            catalog_payload.get("coverage", {}).get("counts", {})
        ),
        "machine_projection": {
            "status": "checked",
            "entry_rvas": [item["rva"] for item in boundary.get("entries", [])],
            "external_exit_count": len(component_call_plan["remaining_exits"]),
            "call_closure": copy.deepcopy(boundary.get("call_closure", {})),
            "selected_component_calls": copy.deepcopy(
                component_call_plan["calls"]
            ),
            "internal_call_frames": copy.deepcopy(
                boundary.get("effects", {}).get("internal_call_frames", [])
            ),
            "control_and_faults_preserved_by": "generated_machine_adapter_v1",
        },
        "adapter_effect_plan": {
            "ordering": "machine_boundary_order",
            "memory": copy.deepcopy(
                boundary.get("effects", {}).get("memory_events", [])
            ),
            "external_events": copy.deepcopy(component_call_plan["remaining_events"]),
            "component_calls": copy.deepcopy(component_call_plan["calls"]),
            "internal_call_frames": copy.deepcopy(
                boundary.get("effects", {}).get("internal_call_frames", [])
            ),
            "exits": copy.deepcopy(component_call_plan["remaining_exits"]),
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
            "logical_interface_refinement_sha256": checked_interface[
                "refinement_sha256"
            ],
        },
        "files": {
            "backend_workspace": "workspace.json",
            "refinement": "contract/component-refinement.json",
            "portable_source": backend_workspace["files"]["portable_source"],
            "portable_header": backend_workspace["files"]["portable_header"],
            "machine_adapter_source": backend_workspace["files"]["machine_adapter_source"],
            "generated_adapter_reference": "contract/generated-machine-adapter.c",
            "logical_interface_refinement": (
                "contract/checked-logical-interface.json"
            ),
            **(
                {"finite_component_contract": "contract/finite-component-contract.json"}
                if finite_contract is not None
                else {}
            ),
            **(
                {"bounded_string_contract": "contract/bounded-string-contract.json"}
                if bounded_string_contract is not None
                else {}
            ),
            **(
                {
                    prepared_profile.contract_field: (
                        f"contract/{prepared_profile.contract_filename}"
                    )
                }
                if prepared_profile is not None
                else {}
            ),
            "replacement_manifest": backend_workspace["files"]["replacement_manifest"],
        },
        "activation": {
            "status": "blocked_pending_qualification",
            "required_artifact": COMPONENT_QUALIFICATION_FORMAT,
            "domain": (
                {
                    "kind": "guarded_partial",
                    "max_range_words": _BOUNDED_RANGE_ROTATION_WORDS,
                    "original_stack_frame_bytes": 64,
                    "requires_readable_writable_range": True,
                    "fallback": "canonical_machine_ir",
                    "decline_before_guest_writes": True,
                    "decline_before_observable_effects": True,
                }
                if proof_profile == "bounded_range_rotation_v1"
                else (
                    {
                        "kind": "guarded_partial",
                        "max_bytes": _BOUNDED_STRING_LENGTH_BYTES,
                        "requires_readable_stack_frame": True,
                        "requires_readable_string_prefix": True,
                        "fallback": "canonical_machine_ir",
                        "decline_before_guest_writes": True,
                        "decline_before_observable_effects": True,
                    }
                    if proof_profile == "bounded_string_length_v1"
                    else (
                        prepared_profile.activation_domain
                        if prepared_profile is not None
                        else {"kind": "total"}
                    )
                )
            ),
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
    backend = rebind_component_backend_workspace(workspace=root)
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
    interface_refinement = _load_bound_interface_refinement(
        root, metadata, refinement
    )
    source = root / metadata["files"]["portable_source"]
    header = root / metadata["files"]["portable_header"]
    profile_name = str(metadata["proof_profile"])
    profile_implementation = load_component_profile(profile_name)
    harness = (
        profile_implementation.render_cbmc_harness(refinement)
        if profile_implementation is not None
        else _render_cbmc_harness(profile=profile_name, refinement=refinement)
    )
    harness_path = Path(out).parent / "component-cbmc-harness.c"
    harness_path.parent.mkdir(parents=True, exist_ok=True)
    harness_path.write_text(harness, encoding="ascii")
    if profile_implementation is not None:
        unwind = profile_implementation.cbmc_unwind(refinement)
    elif metadata["proof_profile"] == "bounded_range_rotation_v1":
        unwind = 8
    elif metadata["proof_profile"] == "bounded_string_length_v1":
        contract = _bounded_string_contract_from_refinement(refinement)
        unwind = int(contract["domain"]["max_bytes"]) + 2
    elif metadata["proof_profile"] == "finite_acyclic_scalar_v1":
        unwind = 2
    elif metadata["proof_profile"] == "finite_acyclic_static_string_lookup_v1":
        contract = _finite_contract_from_refinement(refinement)
        unwind = max(
            int(row["length_with_nul"])
            for row in _array(
                contract["result"].get("values"), "finite result values"
            )
        ) + 1
    else:
        unwind = 6
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
        str(unwind),
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
            "kind": "bounded_model_check",
            "proof_profile": metadata["proof_profile"],
            "unwind": unwind,
            **(
                dict(profile_implementation.evidence_scope(refinement))
                if profile_implementation is not None
                else {}
            ),
            **(
                {
                    "complete_for_range_words_at_most": (
                        _BOUNDED_RANGE_ROTATION_WORDS
                    ),
                    "outside_domain": "decline_to_canonical_machine_ir",
                }
                if metadata["proof_profile"] == "bounded_range_rotation_v1"
                else {}
            ),
            **(
                {
                    "complete_for_string_bytes_at_most": int(
                        _bounded_string_contract_from_refinement(refinement)[
                            "domain"
                        ]["max_bytes"]
                    ),
                    "outside_domain": "decline_to_canonical_machine_ir",
                }
                if metadata["proof_profile"] == "bounded_string_length_v1"
                else {}
            ),
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
    interface_refinement = _load_bound_interface_refinement(
        root, metadata, refinement
    )
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
            "logical_interface_refinement",
            interface_refinement.get("status") == "checked"
            and interface_refinement.get("issues") in (None, []),
            interface_refinement.get("status"),
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
        _check(
            "component_call_dependencies",
            _component_call_dependency_status(root, refinement) in {
                "checked",
                "not_applicable",
            },
            _component_call_dependency_status(root, refinement),
        ),
    ]
    replacement_manifest = _read_object(
        root / metadata["files"]["replacement_manifest"],
        "region replacement manifest",
    )
    declared_unit_ids = {
        str(value) for value in refinement.get("component", {}).get("unit_ids", [])
    }
    manifest_unit_ids = {
        str(value)
        for value in replacement_manifest.get("cluster", {}).get("unit_ids", [])
    }
    checks.append(
        _check(
            "exact_component_membership",
            bool(declared_unit_ids) and manifest_unit_ids == declared_unit_ids,
            (
                "exact"
                if bool(declared_unit_ids) and manifest_unit_ids == declared_unit_ids
                else {
                    "declared": sorted(declared_unit_ids),
                    "replacement_manifest": sorted(manifest_unit_ids),
                }
            ),
        )
    )
    activation_domain = _object(
        metadata.get("activation", {}).get("domain", {"kind": "total"}),
        "component activation domain",
    )
    if activation_domain.get("kind") == "guarded_partial":
        scope = evidence.get("scope", {})
        profile = metadata.get("proof_profile")
        profile_implementation = load_component_profile(str(profile))
        if profile_implementation is not None:
            domain_matches = profile_implementation.activation_scope_matches(
                activation_domain=activation_domain,
                evidence_scope=scope,
            )
        elif profile == "bounded_range_rotation_v1":
            domain_matches = (
                scope.get("complete_for_range_words_at_most")
                == activation_domain.get("max_range_words")
            )
        elif profile == "bounded_string_length_v1":
            domain_matches = (
                scope.get("complete_for_string_bytes_at_most")
                == activation_domain.get("max_bytes")
            )
        else:
            domain_matches = False
        checks.append(
            _check(
                "guarded_partial_domain",
                domain_matches
                and scope.get("kind") == "bounded_model_check"
                and scope.get("outside_domain")
                == "decline_to_canonical_machine_ir"
                and activation_domain.get("decline_before_guest_writes") is True
                and activation_domain.get("decline_before_observable_effects")
                is True
                and activation_domain.get("fallback") == "canonical_machine_ir",
                "checked" if domain_matches else "stale",
            )
        )
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
        "component": copy.deepcopy(refinement["component"]),
        **(
            {
                "component_contract": copy.deepcopy(
                    refinement["component_contract"]
                )
            }
            if isinstance(refinement.get("component_contract"), Mapping)
            else {}
        ),
        "implementation": {
            "portable_source_sha256": refinement["bindings"][
                "portable_source_sha256"
            ],
            "portable_symbol": refinement["portable_symbol"],
            "proof_profile": refinement.get(
                "proof_profile", metadata["proof_profile"]
            ),
        },
        "bindings": {
            "component_workspace_sha256": metadata["workspace_sha256"],
            "refinement_sha256": refinement["refinement_sha256"],
            "source_evidence_sha256": sha256_file(evidence_path),
            "replacement_manifest_sha256": replacement_manifest["manifest_sha256"],
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
            "domain": copy.deepcopy(activation_domain),
        },
    }
    payload = {
        **payload_core,
        "qualification_sha256": _canonical_sha256(payload_core),
    }
    write_json(Path(out), payload)
    return payload


def promote_qualified_components(
    *,
    workspaces: Sequence[Path],
    qualifications: Sequence[Path],
    out_dir: Path,
    machine_unit_count: int | None = None,
    linked_islands: Path | Mapping[str, Any] | None = None,
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
    partial_roots = [
        root
        for root, qualification in qualified
        if qualification.get("activation", {}).get("domain", {}).get("kind")
        == "guarded_partial"
    ]
    backend = promote_component_backend_workspaces(
        workspaces=[item[0] for item in qualified],
        out_dir=out_dir,
        fallback_on_unimplemented_workspaces=partial_roots,
    )
    entries = []
    qualified_unit_ids: set[str] = set()
    partial_unit_ids: set[str] = set()
    global_counts: Mapping[str, Any] | None = None
    for root, qualification in sorted(qualified, key=lambda item: str(item[1]["component_id"])):
        metadata = _load_component_workspace(root)
        refinement = _load_bound_refinement(root, metadata)
        domain = _object(
            qualification.get("activation", {}).get("domain", {"kind": "total"}),
            "component qualification activation domain",
        )
        unit_ids = {str(value) for value in refinement["component"]["unit_ids"]}
        if domain.get("kind") == "total":
            qualified_unit_ids.update(unit_ids)
        elif domain.get("kind") == "guarded_partial":
            partial_unit_ids.update(unit_ids)
        else:
            raise StageAInputError(
                f"unsupported component activation domain: {domain.get('kind')}"
            )
        observed_counts = refinement.get("global_coverage_counts", {})
        if observed_counts:
            if global_counts is None:
                global_counts = observed_counts
            elif observed_counts != global_counts:
                raise StageAInputError(
                    "qualified components disagree on global coverage counts"
                )
        entries.append(
            {
                "component_id": metadata["component_id"],
                "proof_profile": metadata["proof_profile"],
                "qualification_sha256": qualification["qualification_sha256"],
                "workspace_sha256": metadata["workspace_sha256"],
                "domain": copy.deepcopy(domain),
                "entry_rva": _read_object(
                    root / metadata["files"]["replacement_manifest"],
                    "region replacement manifest",
                )["cluster"]["entry_rva"],
            }
        )
    if machine_unit_count is not None and machine_unit_count < 0:
        raise StageAInputError("machine unit count cannot be negative")
    machine_units = (
        machine_unit_count
        if machine_unit_count is not None
        else (None if global_counts is None else global_counts.get("machine_units"))
    )
    remaining_units = (
        None
        if not isinstance(machine_units, int)
        else int(machine_units) - len(qualified_unit_ids)
    )
    linked_coverage = _promoted_linked_island_coverage(
        linked_islands,
        qualified_unit_ids=qualified_unit_ids,
        partial_unit_ids=partial_unit_ids - qualified_unit_ids,
        machine_unit_count=machine_units,
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
        "counts": {
            "components": len(entries),
            "total_components": len(entries) - len(partial_roots),
            "partial_components": len(partial_roots),
            "replacements": len(entries),
        },
        "whole_program_status": (
            "qualified" if remaining_units == 0 else "incomplete"
        ),
        "coverage": {
            "qualified_unit_ids": sorted(qualified_unit_ids),
            "qualified_units": len(qualified_unit_ids),
            "partial_unit_ids": sorted(partial_unit_ids - qualified_unit_ids),
            "partial_units": len(partial_unit_ids - qualified_unit_ids),
            "machine_units": machine_units,
            "remaining_units": remaining_units,
            **(
                {"linked_islands": linked_coverage}
                if linked_coverage is not None
                else {}
            ),
            "interpretation": (
                "component qualification authorizes only listed override entries; "
                "it does not claim whole-program reconstruction"
            ),
        },
    }
    payload = {**payload_core, "registry_sha256": _canonical_sha256(payload_core)}
    write_json(out_dir / "component-registry.json", payload)
    return payload


def _promoted_linked_island_coverage(
    linked_islands: Path | Mapping[str, Any] | None,
    *,
    qualified_unit_ids: set[str],
    partial_unit_ids: set[str],
    machine_unit_count: int | None,
) -> dict[str, Any] | None:
    if linked_islands is None:
        return None
    manifest = (
        copy.deepcopy(dict(linked_islands))
        if isinstance(linked_islands, Mapping)
        else _read_object(Path(linked_islands), "linked-island manifest")
    )
    try:
        validate_linked_island_manifest(manifest)
    except LinkedLibraryContractError as error:
        raise StageAInputError(f"invalid linked-island manifest: {error}") from error
    owner_by_unit: dict[str, Mapping[str, Any]] = {}
    totals: dict[str, int] = {}
    for raw_island in manifest.get("islands", []):
        island = _object(raw_island, "linked island")
        kind = str(island["kind"])
        for raw_unit_id in island.get("unit_ids", []):
            unit_id = str(raw_unit_id)
            owner_by_unit[unit_id] = island
            totals[kind] = totals.get(kind, 0) + 1
    if machine_unit_count is not None and len(owner_by_unit) != machine_unit_count:
        raise StageAInputError(
            "linked-island manifest/machine unit count mismatch during promotion"
        )
    unknown_qualified = (qualified_unit_ids | partial_unit_ids) - set(owner_by_unit)
    if unknown_qualified:
        raise StageAInputError(
            "qualified components reference units absent from linked islands: "
            f"{sorted(unknown_qualified)[:8]}"
        )
    qualified_by_kind: dict[str, int] = {}
    partial_by_kind: dict[str, int] = {}
    for unit_id in qualified_unit_ids:
        kind = str(owner_by_unit[unit_id]["kind"])
        qualified_by_kind[kind] = qualified_by_kind.get(kind, 0) + 1
    for unit_id in partial_unit_ids:
        kind = str(owner_by_unit[unit_id]["kind"])
        partial_by_kind[kind] = partial_by_kind.get(kind, 0) + 1
    return {
        "manifest_sha256": manifest["manifest_sha256"],
        "machine_units_by_kind": dict(sorted(totals.items())),
        "qualified_units_by_kind": dict(sorted(qualified_by_kind.items())),
        "partial_units_by_kind": dict(sorted(partial_by_kind.items())),
        "remaining_units_by_kind": {
            kind: count
            - qualified_by_kind.get(kind, 0)
            - partial_by_kind.get(kind, 0)
            for kind, count in sorted(totals.items())
        },
        "identity_authorizes_activation": False,
    }


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
    elif profile == "constant_compare_branch_v1":
        descriptor = _constant_compare_descriptor(refinement["logical_interface"])
        comparison = "==" if descriptor["taken_on_equal"] else "!="
        body = f"""
int main(void) {{
  uint{descriptor['width']}_t value = (uint{descriptor['width']}_t)nondet_u32();
  bool route = {symbol}(value);
  __CPROVER_assert(route == (value {comparison} UINT{descriptor['width']}_C({descriptor['constant']})), "constant comparison route");
  return 0;
}}
"""
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
    elif profile == "bounded_range_rotation_v1":
        assignments = "\n".join(
            f"  words[{index}] = nondet_u32(); original[{index}] = words[{index}];"
            for index in range(_BOUNDED_RANGE_ROTATION_WORDS)
        )
        assertions = "\n".join(
            f"  __CPROVER_assert(words[{index}] == expected_word(original, {index}U, old_first, old_middle, old_end), \"word {index}\");"
            for index in range(_BOUNDED_RANGE_ROTATION_WORDS)
        )
        body = f"""
static uint32_t expected_word(const uint32_t *original, uint32_t index,
                              uint32_t first, uint32_t middle, uint32_t end) {{
  uint32_t left = middle - first;
  if (index < first || index >= end) return original[index];
  return index + left < end
      ? original[index + left]
      : original[first + index + left - end];
}}
int main(void) {{
  uint32_t words[{_BOUNDED_RANGE_ROTATION_WORDS}];
  uint32_t original[{_BOUNDED_RANGE_ROTATION_WORDS}];
  reconstructed_range_window window;
{assignments}
  window.first = nondet_u32();
  window.middle = nondet_u32();
  window.end = nondet_u32();
  __CPROVER_assume(window.first <= window.middle);
  __CPROVER_assume(window.middle <= window.end);
  __CPROVER_assume(window.end <= UINT32_C({_BOUNDED_RANGE_ROTATION_WORDS}));
  uint32_t old_first = window.first;
  uint32_t old_middle = window.middle;
  uint32_t old_end = window.end;
  __CPROVER_assert({symbol}(words, UINT32_C({_BOUNDED_RANGE_ROTATION_WORDS}), &window), "implemented");
  __CPROVER_assert(window.first == old_first + old_end - old_middle, "updated first");
  __CPROVER_assert(window.middle == old_end, "updated middle");
  __CPROVER_assert(window.end == old_end, "preserved end");
{assertions}
  return 0;
}}
"""
    elif profile == "bounded_string_length_v1":
        contract = _bounded_string_contract_from_refinement(refinement)
        maximum = int(_object(contract.get("domain"), "bounded string domain")["max_bytes"])
        assignments = "\n".join(
            f"  bytes[{index}] = (uint8_t)nondet_u32();"
            for index in range(maximum)
        )
        body = f"""
int main(void) {{
  uint8_t bytes[{maximum}];
  uint32_t limit = nondet_u32();
  uint32_t expected = 0U;
{assignments}
  __CPROVER_assume(limit <= UINT32_C({maximum}));
  while (expected < limit && bytes[expected] != 0U)
    ++expected;
  __CPROVER_assert({symbol}(bytes, limit) == expected, "bounded string length");
  return 0;
}}
"""
    elif profile == "bounded_pairwise_byte_compare_v1":
        contract = _bounded_pairwise_contract_from_refinement(refinement)
        maximum = int(_object(contract.get("domain"), "bounded pairwise domain")["max_bytes"])
        dependency = _object(
            contract.get("component_call"), "bounded pairwise component call"
        )
        scalar_contract = _object(
            dependency.get("finite_component_contract"),
            "bounded pairwise scalar contract",
        )
        normalize_body = _render_scalar_piecewise_returns(
            contract=scalar_contract,
            output_path=("output",),
            indent="  ",
        )
        assignments = "\n".join(
            (
                f"  left[{index}] = (uint8_t)nondet_u32();\n"
                f"  right[{index}] = (uint8_t)nondet_u32();"
            )
            for index in range(maximum)
        )
        body = f"""
static inline uint32_t semantic_parity(uint32_t value) {{
  value ^= value >> 4;
  value &= UINT32_C(0x0f);
  return (UINT32_C(0x9669) >> value) & UINT32_C(1);
}}
static uint32_t expected_normalize(uint32_t input) {{
{normalize_body}
}}
int main(void) {{
  uint8_t left[{maximum}];
  uint8_t right[{maximum}];
  uint32_t index;
  int32_t expected = 0;
  bool decided = false;
{assignments}
  for (index = 0U; index < UINT32_C({maximum}); ++index) {{
    uint32_t left_value = expected_normalize(left[index]);
    uint32_t right_value = expected_normalize(right[index]);
    if (left_value == 0U || left_value != right_value) {{
      expected = (int32_t)(uint32_t)(left_value - right_value);
      decided = true;
      break;
    }}
  }}
  __CPROVER_assume(decided);
  __CPROVER_assert({symbol}(left, right) == expected,
                   "bounded pairwise comparison");
  __CPROVER_assert({symbol}(left, left) == 0,
                   "pairwise pointer identity");
  return 0;
}}
"""
    elif profile == "finite_acyclic_scalar_v1":
        contract = _finite_contract_from_refinement(refinement)
        expected_body = _render_scalar_piecewise_returns(
            contract=contract,
            output_path=("output",),
            indent="  ",
        )
        body = f"""
static inline uint32_t semantic_parity(uint32_t value) {{
  value ^= value >> 4;
  value &= UINT32_C(0x0f);
  return (UINT32_C(0x9669) >> value) & UINT32_C(1);
}}
static uint32_t expected_scalar(uint32_t input) {{
{expected_body}
}}
int main(void) {{
  uint32_t input = nondet_u32();
  __CPROVER_assert({symbol}(input) == expected_scalar(input),
                   "finite scalar result");
  return 0;
}}
"""
    elif profile == "finite_acyclic_static_string_lookup_v1":
        contract = _finite_contract_from_refinement(refinement)
        cases = _array(contract["result"].get("cases"), "finite result cases")
        values = {
            str(row["id"]): row
            for row in _array(contract["result"].get("values"), "finite result values")
        }
        switch_rows = "\n".join(
            "    case UINT32_C(0x{input_bits:08x}): return {literal};".format(
                input_bits=int(row["input_bits"]),
                literal=_c_string_literal(str(values[str(row["value_id"])]["text"])),
            )
            for row in cases
        )
        maximum = max((int(row["length_with_nul"]) for row in values.values()), default=1)
        body = f"""
static const char *expected_value(uint32_t input) {{
  switch (input) {{
{switch_rows}
    default: return (const char *)0;
  }}
}}
static bool same_string(const char *left, const char *right) {{
  uint32_t index;
  if (left == (const char *)0 || right == (const char *)0)
    return left == right;
  for (index = 0U; index < UINT32_C({maximum}); ++index) {{
    if (left[index] != right[index]) return false;
    if (left[index] == '\\0') return true;
  }}
  return false;
}}
int main(void) {{
  uint32_t input = nondet_u32();
  const char *expected = expected_value(input);
  const char *observed = {symbol}((int32_t)input);
  __CPROVER_assert(same_string(observed, expected), "finite static string result");
  return 0;
}}
"""
    else:
        raise StageAInputError(f"unsupported component proof profile: {profile}")
    return (
        '#include "implementation.h"\n'
        "#include <stdbool.h>\n"
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


def _finite_contract_from_refinement(
    refinement: Mapping[str, Any],
) -> Mapping[str, Any]:
    contract = _object(
        refinement.get("finite_component_contract"),
        "finite component contract",
    )
    if (
        contract.get("format") != FINITE_COMPONENT_CONTRACT_FORMAT
        or contract.get("status") != "derived"
        or contract.get("executes_original_binary") is not False
    ):
        raise StageAInputError("finite component contract is not a usable static derivation")
    expected = contract.get("contract_sha256")
    core = copy.deepcopy(dict(contract))
    core.pop("contract_sha256", None)
    if expected != _canonical_sha256(core):
        raise StageAInputError("finite component contract self-hash is stale")
    return contract


def _bounded_string_contract_from_refinement(
    refinement: Mapping[str, Any],
) -> Mapping[str, Any]:
    contract = _object(
        refinement.get("bounded_string_contract"),
        "bounded string contract",
    )
    validate_bounded_string_contract(contract)
    if contract.get("format") != BOUNDED_STRING_CONTRACT_FORMAT:
        raise StageAInputError("bounded string contract is not a usable static derivation")
    return contract


def _bounded_pairwise_contract_from_refinement(
    refinement: Mapping[str, Any],
) -> Mapping[str, Any]:
    contract = _object(
        refinement.get("bounded_pairwise_byte_contract"),
        "bounded pairwise byte contract",
    )
    validate_bounded_pairwise_byte_contract(contract)
    if contract.get("format") != BOUNDED_PAIRWISE_BYTE_CONTRACT_FORMAT:
        raise StageAInputError(
            "bounded pairwise byte contract is not a usable static derivation"
        )
    return contract


def _component_proof_contract_from_refinement(
    refinement: Mapping[str, Any],
) -> dict[str, Any]:
    """Return the profile-independent, self-bound child contract."""

    descriptor = refinement.get("component_contract")
    if descriptor is None:
        # Compatibility for workspaces produced before generic component
        # contract descriptors were introduced.
        payload = _finite_contract_from_refinement(refinement)
        return {
            "field": "finite_component_contract",
            "format": str(payload["format"]),
            "contract_sha256": str(payload["contract_sha256"]),
            "payload": copy.deepcopy(payload),
        }
    descriptor = _object(descriptor, "component proof contract descriptor")
    field = descriptor.get("field")
    contract_format = descriptor.get("format")
    contract_sha256 = descriptor.get("contract_sha256")
    if (
        not isinstance(field, str)
        or not field
        or not isinstance(contract_format, str)
        or not contract_format
        or not isinstance(contract_sha256, str)
        or not contract_sha256
    ):
        raise StageAInputError("component proof contract descriptor is malformed")
    payload = _object(refinement.get(field), "component proof contract payload")
    payload_core = copy.deepcopy(dict(payload))
    observed_sha256 = payload_core.pop("contract_sha256", None)
    if (
        payload.get("format") != contract_format
        or observed_sha256 != contract_sha256
        or observed_sha256 != _canonical_sha256(payload_core)
    ):
        raise StageAInputError("component proof contract payload is stale")
    return {
        "field": field,
        "format": contract_format,
        "contract_sha256": contract_sha256,
        "payload": copy.deepcopy(payload),
    }


def _c_string_literal(value: str) -> str:
    if not isinstance(value, str) or "\x00" in value:
        raise StageAInputError("portable C string values must be NUL-free text")
    try:
        value.encode("ascii")
    except UnicodeEncodeError as error:
        raise StageAInputError("portable C string values must currently be ASCII") from error
    return json.dumps(value, ensure_ascii=True)


def _validate_profile_shape(
    profile: str,
    component: Mapping[str, Any],
    cluster: Mapping[str, Any],
    *,
    component_dependencies: Sequence[Mapping[str, Any]],
) -> None:
    template = str(cluster.get("template") or "manual_contract")
    allowed_templates = {
        "compare_branch_v1": {"compare_branch"},
        "constant_compare_branch_v1": {"manual_contract"},
        # The reconstruction template is an untrusted generation hint. A
        # checked service interface may refine either the specialized hint or
        # a conservative manual-contract cluster.
        "constant_service_call_v1": {
            "constant_external_call",
            "manual_contract",
        },
        "store_then_zero_call_v1": {"store_then_zero_call"},
        "atomic_compare_exchange_v1": {"manual_contract"},
        "finite_dispatch_v1": {"manual_contract"},
        "alias_sensitive_word_update_v1": {"manual_contract"},
        "bounded_range_rotation_v1": {"manual_contract"},
        "bounded_string_length_v1": {"manual_contract"},
        "bounded_pairwise_byte_compare_v1": {"manual_contract"},
        "finite_acyclic_scalar_v1": {"manual_contract"},
        "finite_acyclic_static_string_lookup_v1": {"manual_contract"},
    }[profile]
    if template not in allowed_templates:
        raise StageAInputError(
            f"proof profile {profile} requires one of "
            f"{sorted(allowed_templates)}, observed {template}"
        )
    if profile == "constant_compare_branch_v1":
        boundary = component.get("machine_boundary", {})
        if (
            boundary.get("counts", {}).get("memory_events") != 0
            or boundary.get("counts", {}).get("external_events") != 0
            or len(boundary.get("exits", [])) != 2
        ):
            raise StageAInputError(
                "constant comparison component requires two pure control exits"
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
    if profile == "bounded_range_rotation_v1":
        if (
            boundary.get("call_closure", {}).get("status") != "complete"
            or boundary.get("counts", {}).get("entries") != 1
            or boundary.get("counts", {}).get("exits") != 1
            or boundary.get("counts", {}).get("external_events") != 0
        ):
            raise StageAInputError(
                "bounded range rotation requires one closed, internal-only return region"
            )
    if profile == "bounded_string_length_v1":
        if (
            boundary.get("call_closure", {}).get("status") != "complete"
            or boundary.get("counts", {}).get("entries") != 1
            or boundary.get("counts", {}).get("exits") != 1
            or boundary.get("counts", {}).get("external_events") != 0
            or boundary.get("counts", {}).get("faults") != 0
            or len(boundary.get("internal_calls", [])) != 0
            or boundary.get("exits", [{}])[0].get("kind") != "return"
        ):
            raise StageAInputError(
                "bounded string length requires one closed, pure return region"
            )
    if profile == "bounded_pairwise_byte_compare_v1":
        exits = _array(boundary.get("exits"), "component machine exits")
        calls = [item for item in exits if item.get("kind") == "internal_call"]
        returns = [item for item in exits if item.get("kind") == "return"]
        if (
            boundary.get("call_closure", {}).get("status") != "complete"
            or boundary.get("counts", {}).get("entries") != 1
            or boundary.get("counts", {}).get("faults") != 0
            or len(calls) != 2
            or len(returns) != 1
            or len(component_dependencies) != 1
        ):
            raise StageAInputError(
                "bounded pairwise comparison requires two qualified scalar calls and one return"
            )
    if profile in {
        "finite_acyclic_scalar_v1",
        "finite_acyclic_static_string_lookup_v1",
    }:
        if (
            boundary.get("call_closure", {}).get("status") != "complete"
            or boundary.get("counts", {}).get("entries") != 1
            or boundary.get("counts", {}).get("exits") != 1
            or boundary.get("counts", {}).get("external_events") != 0
            or boundary.get("counts", {}).get("faults") != 0
            or len(boundary.get("internal_calls", [])) != 0
            or boundary.get("exits", [{}])[0].get("kind") != "return"
        ):
            raise StageAInputError(
                "finite acyclic component requires one closed, pure return region"
            )


def _install_logical_profile_sources(
    *,
    root: Path,
    backend_workspace: Mapping[str, Any],
    profile: str,
    interface_refinement: Mapping[str, Any],
    entry_rva: int,
    finite_contract: Mapping[str, Any] | None,
    bounded_string_contract: Mapping[str, Any] | None,
    bounded_pairwise_contract: Mapping[str, Any] | None,
) -> None:
    if profile not in {
        "constant_compare_branch_v1",
        "bounded_range_rotation_v1",
        "bounded_string_length_v1",
        "bounded_pairwise_byte_compare_v1",
        "finite_acyclic_scalar_v1",
        "finite_acyclic_static_string_lookup_v1",
    }:
        return
    files = _object(backend_workspace.get("files"), "backend workspace files")
    adapter_path = root / str(files["machine_adapter_source"])
    adapter_text = adapter_path.read_text(encoding="ascii")
    matches = re.findall(
        r"stage_b_step_result\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(",
        adapter_text,
    )
    if len(matches) != 1:
        raise StageAInputError(
            f"component machine adapter has {len(matches)} replacement symbols"
        )
    logical = _object(
        interface_refinement.get("logical_interface"), "checked logical interface"
    )
    if profile == "bounded_range_rotation_v1":
        _install_range_rotation_sources(
            root=root,
            files=files,
            adapter_path=adapter_path,
            adapter_symbol=matches[0],
            logical=logical,
            entry_rva=entry_rva,
        )
        return
    if profile == "finite_acyclic_scalar_v1":
        if finite_contract is None:
            raise StageAInputError("finite scalar profile omitted its derived contract")
        _install_finite_scalar_sources(
            root=root,
            files=files,
            adapter_path=adapter_path,
            adapter_symbol=matches[0],
            contract=finite_contract,
            entry_rva=entry_rva,
        )
        return
    if profile == "finite_acyclic_static_string_lookup_v1":
        if finite_contract is None:
            raise StageAInputError("finite profile omitted its derived contract")
        _install_finite_static_string_sources(
            root=root,
            files=files,
            adapter_path=adapter_path,
            adapter_symbol=matches[0],
            contract=finite_contract,
            entry_rva=entry_rva,
        )
        return
    if profile == "bounded_string_length_v1":
        if bounded_string_contract is None:
            raise StageAInputError("bounded string profile omitted its derived contract")
        _install_bounded_string_length_sources(
            root=root,
            files=files,
            adapter_path=adapter_path,
            adapter_symbol=matches[0],
            contract=bounded_string_contract,
            entry_rva=entry_rva,
        )
        return
    if profile == "bounded_pairwise_byte_compare_v1":
        if bounded_pairwise_contract is None:
            raise StageAInputError(
                "bounded pairwise profile omitted its derived contract"
            )
        _install_bounded_pairwise_byte_compare_sources(
            root=root,
            files=files,
            adapter_path=adapter_path,
            adapter_symbol=matches[0],
            contract=bounded_pairwise_contract,
            entry_rva=entry_rva,
        )
        return
    descriptor = _constant_compare_descriptor(logical)
    c_type = f"uint{descriptor['width']}_t"
    macro = f"UINT{descriptor['width']}_C"
    comparison = "==" if descriptor["taken_on_equal"] else "!="
    header = f"""#ifndef SPAGHETTI_RECONSTRUCTED_IMPLEMENTATION_H
#define SPAGHETTI_RECONSTRUCTED_IMPLEMENTATION_H

#include <stdbool.h>
#include <stdint.h>

bool classify_value({c_type} value);

#endif
"""
    portable = f"""#include "implementation.h"

bool classify_value({c_type} value) {{
  return value {comparison} {macro}({descriptor['constant']});
}}
"""
    mask = int(descriptor["mask"])
    sign_mask = 1 << (int(descriptor["width"]) - 1)
    adapter_lines = [
        '#include "state-machine-runtime.h"',
        '#include "implementation.h"',
        "",
        "static uint32_t even_parity_low_byte(uint32_t value) {",
        "  value ^= value >> 4;",
        "  value &= UINT32_C(0x0f);",
        "  return (UINT32_C(0x9669) >> value) & UINT32_C(1);",
        "}",
        "",
        f"stage_b_step_result {matches[0]}(stage_b_runtime *rt, stage_b_machine_state *state) {{",
        f"  const uint32_t left = state->{descriptor['register']} & UINT32_C(0x{mask:08x});",
        f"  const uint32_t right = UINT32_C({descriptor['constant']});",
        f"  const uint32_t difference = (left - right) & UINT32_C(0x{mask:08x});",
        f"  const bool route = classify_value(({c_type})left);",
        "  (void)rt;",
        f"  state->original_rva = UINT32_C(0x{entry_rva:08x});",
        "  state->cf = left < right;",
        f"  state->of = ((left ^ right) & (left ^ difference) & UINT32_C(0x{sign_mask:08x})) != 0U;",
        "  state->pf = even_parity_low_byte(difference);",
        f"  state->sf = (difference >> {int(descriptor['width']) - 1}) & UINT32_C(1);",
        "  state->zf = difference == 0U;",
        *_machine_eflags_sync_lines("  "),
        "  return (stage_b_step_result){",
        "      STAGE_B_BRANCH,",
        f"      route ? UINT32_C(0x{int(descriptor['true_target_rva']):08x}) : UINT32_C(0x{int(descriptor['false_target_rva']):08x}),",
        "      0U",
        "  };",
        "}",
        "",
    ]
    (root / str(files["portable_header"])).write_text(header, encoding="ascii")
    (root / str(files["portable_source"])).write_text(portable, encoding="ascii")
    adapter_path.write_text("\n".join(adapter_lines), encoding="ascii")


def _install_range_rotation_sources(
    *,
    root: Path,
    files: Mapping[str, Any],
    adapter_path: Path,
    adapter_symbol: str,
    logical: Mapping[str, Any],
    entry_rva: int,
) -> None:
    _range_rotation_descriptor(logical)
    header = """#ifndef SPAGHETTI_RECONSTRUCTED_IMPLEMENTATION_H
#define SPAGHETTI_RECONSTRUCTED_IMPLEMENTATION_H

#include <stdbool.h>
#include <stdint.h>

typedef struct reconstructed_range_window {
  uint32_t first;
  uint32_t middle;
  uint32_t end;
} reconstructed_range_window;

bool rotate_words(uint32_t *words, uint32_t length,
                  reconstructed_range_window *window);

#endif
"""
    portable = """#include "implementation.h"

static void reverse_words(uint32_t *words, uint32_t first, uint32_t end) {
  while (first < end) {
    uint32_t value;
    --end;
    if (first >= end)
      break;
    value = words[first];
    words[first] = words[end];
    words[end] = value;
    ++first;
  }
}

bool rotate_words(uint32_t *words, uint32_t length,
                  reconstructed_range_window *window) {
  uint32_t old_middle;
  uint32_t old_end;
  if (words == 0 || window == 0 || window->first > window->middle ||
      window->middle > window->end || window->end > length)
    return false;
  old_middle = window->middle;
  old_end = window->end;
  reverse_words(words, window->first, window->middle);
  reverse_words(words, window->middle, window->end);
  reverse_words(words, window->first, window->end);
  window->first += old_end - old_middle;
  window->middle = old_end;
  return true;
}
"""
    lines = [
        '#include "state-machine-runtime.h"',
        '#include "implementation.h"',
        "",
        "static uint32_t ranges_overlap(uint32_t left, uint32_t left_size,",
        "                               uint32_t right, uint32_t right_size) {",
        "  return left < right + right_size && right < left + left_size;",
        "}",
        "",
        f"stage_b_step_result {adapter_symbol}(stage_b_runtime *rt, stage_b_machine_state *state) {{",
        f"  uint32_t words[UINT32_C({_BOUNDED_RANGE_ROTATION_WORDS})] = {{ 0U }};",
        "  reconstructed_range_window window;",
        "  uint32_t fault = 0U, first, middle, end, count, word_base, index;",
        "  uint32_t stack_start, return_target;",
        f"  middle = rt->read(rt->context, state->edx + UINT32_C(32), UINT32_C(4), &fault);",
        "  if (fault) return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, state->original_rva, 0U };",
        f"  first = rt->read(rt->context, state->edx + UINT32_C(28), UINT32_C(4), &fault);",
        "  if (fault) return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, state->original_rva, 0U };",
        "  end = rt->read(rt->context, state->edx, UINT32_C(4), &fault);",
        "  if (fault) return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, state->original_rva, 0U };",
        "  if (first > middle || middle > end || end > UINT32_C(0x7fffffff) ||",
        f"      end - first > UINT32_C({_BOUNDED_RANGE_ROTATION_WORDS}) ||",
        "      first > UINT32_C(0x3fffffff) ||",
        "      state->eax > UINT32_MAX - first * UINT32_C(4) ||",
        "      state->edx > UINT32_MAX - UINT32_C(36) ||",
        "      state->esp < UINT32_C(64) || state->esp > UINT32_MAX - UINT32_C(4))",
        f"    return (stage_b_step_result){{ STAGE_B_UNIMPLEMENTED, UINT32_C(0x{entry_rva:08x}), 0U }};",
        "  count = end - first;",
        "  word_base = state->eax + first * UINT32_C(4);",
        "  if (word_base > UINT32_MAX - count * UINT32_C(4))",
        f"    return (stage_b_step_result){{ STAGE_B_UNIMPLEMENTED, UINT32_C(0x{entry_rva:08x}), 0U }};",
        "  stack_start = state->esp - UINT32_C(64);",
        "  if (ranges_overlap(word_base, count * UINT32_C(4), stack_start, UINT32_C(68)) ||",
        "      ranges_overlap(state->edx, UINT32_C(36), stack_start, UINT32_C(68)))",
        f"    return (stage_b_step_result){{ STAGE_B_UNIMPLEMENTED, UINT32_C(0x{entry_rva:08x}), 0U }};",
        "  for (index = 0U; index < count; ++index) {",
        "    words[index] = rt->read(rt->context, word_base + index * UINT32_C(4), UINT32_C(4), &fault);",
        "    if (fault) return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, state->original_rva, 0U };",
        "  }",
        "  window.first = 0U;",
        "  window.middle = middle - first;",
        "  window.end = count;",
        f"  if (!rotate_words(words, UINT32_C({_BOUNDED_RANGE_ROTATION_WORDS}), &window))",
        f"    return (stage_b_step_result){{ STAGE_B_UNIMPLEMENTED, UINT32_C(0x{entry_rva:08x}), 0U }};",
        "  for (index = 0U; index < count; ++index) {",
        "    rt->write(rt->context, word_base + index * UINT32_C(4), UINT32_C(4), words[index], &fault);",
        "    if (fault) return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, state->original_rva, 0U };",
        "  }",
        "  rt->write(rt->context, state->edx + UINT32_C(32), UINT32_C(4), end, &fault);",
        "  if (fault) return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, state->original_rva, 0U };",
        "  rt->write(rt->context, state->edx + UINT32_C(28), UINT32_C(4), first + end - middle, &fault);",
        "  if (fault) return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, state->original_rva, 0U };",
        "  return_target = rt->read(rt->context, state->esp, UINT32_C(4), &fault);",
        "  if (fault) return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, state->original_rva, 0U };",
        f"  state->original_rva = UINT32_C(0x{entry_rva:08x});",
        "  state->esp += UINT32_C(4);",
        "  state->eax = 0U;",
        "  state->ecx = 0U;",
        "  state->edx = 0U;",
        "  state->cf = 0U;",
        "  state->of = 0U;",
        "  state->pf = 1U;",
        "  state->sf = 0U;",
        "  state->zf = 1U;",
        *_machine_eflags_sync_lines("  "),
        "  return (stage_b_step_result){ STAGE_B_RETURN, 0U, return_target };",
        "}",
        "",
    ]
    (root / str(files["portable_header"])).write_text(header, encoding="ascii")
    (root / str(files["portable_source"])).write_text(portable, encoding="ascii")
    adapter_path.write_text("\n".join(lines), encoding="ascii")


def _install_finite_scalar_sources(
    *,
    root: Path,
    files: Mapping[str, Any],
    adapter_path: Path,
    adapter_symbol: str,
    contract: Mapping[str, Any],
    entry_rva: int,
) -> None:
    if contract.get("profile") != "finite_acyclic_scalar_v1":
        raise StageAInputError("finite scalar contract has an unsupported profile")
    projection = _object(
        contract.get("machine_projection"), "finite scalar machine projection"
    )
    registers = _string_array(
        projection.get("registers_written"), "finite scalar written registers"
    )
    flags = _string_array(
        projection.get("flags_written"), "finite scalar written flags"
    )
    if "eax" not in registers or any(
        name not in {"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp"}
        for name in registers
    ):
        raise StageAInputError("finite scalar register projection is unsupported")
    if any(name not in {"cf", "of", "pf", "sf", "zf"} for name in flags):
        raise StageAInputError("finite scalar flag projection is unsupported")

    portable_returns = _render_scalar_piecewise_returns(
        contract=contract,
        output_path=("output",),
        indent="  ",
    )
    portable_helper = (
        """static inline uint32_t semantic_parity(uint32_t value) {
  value ^= value >> 4;
  value &= UINT32_C(0x0f);
  return (UINT32_C(0x9669) >> value) & UINT32_C(1);
}

"""
        if "semantic_parity(" in portable_returns
        else ""
    )
    header = """#ifndef SPAGHETTI_RECONSTRUCTED_IMPLEMENTATION_H
#define SPAGHETTI_RECONSTRUCTED_IMPLEMENTATION_H

#include <stdint.h>

uint32_t compute_scalar(uint32_t input);

#endif
"""
    portable = f"""#include "implementation.h"

{portable_helper}
uint32_t compute_scalar(uint32_t input) {{
{portable_returns}
}}
"""
    adapter_lines = [
        '#include "state-machine-runtime.h"',
        '#include "implementation.h"',
        "",
        "static inline uint32_t semantic_parity(uint32_t value) {",
        "  value ^= value >> 4;",
        "  value &= UINT32_C(0x0f);",
        "  return (UINT32_C(0x9669) >> value) & UINT32_C(1);",
        "}",
        "",
    ]
    for name in [*registers, *flags]:
        if name == "eax":
            continue
        adapter_lines.extend(
            [
                f"static uint32_t projected_{name}(uint32_t input) {{",
                "  (void)input;",
                _render_scalar_piecewise_returns(
                    contract=contract,
                    output_path=(
                        "machine_outputs",
                        "registers" if name in registers else "flags",
                        name,
                    ),
                    indent="  ",
                ),
                "}",
                "",
            ]
        )
    adapter_lines.extend(
        [
            f"stage_b_step_result {adapter_symbol}(stage_b_runtime *rt, stage_b_machine_state *state) {{",
            "  uint32_t fault = 0U, input, return_target;",
            "  input = rt->read(rt->context, state->esp + UINT32_C(4), UINT32_C(4), &fault);",
            "  if (fault) return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, state->original_rva, 0U };",
            "  return_target = rt->read(rt->context, state->esp, UINT32_C(4), &fault);",
            "  if (fault) return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, state->original_rva, 0U };",
            f"  state->original_rva = UINT32_C(0x{entry_rva:08x});",
            "  state->eax = compute_scalar(input);",
            *(
                f"  state->{name} = projected_{name}(input);"
                for name in registers
                if name != "eax"
            ),
            *(f"  state->{name} = projected_{name}(input);" for name in flags),
            "  state->esp += UINT32_C(4);",
            *_machine_eflags_sync_lines("  "),
            "  return (stage_b_step_result){ STAGE_B_RETURN, 0U, return_target };",
            "}",
            "",
        ]
    )
    (root / str(files["portable_header"])).write_text(header, encoding="ascii")
    (root / str(files["portable_source"])).write_text(portable, encoding="ascii")
    adapter_path.write_text("\n".join(adapter_lines), encoding="ascii")


def _render_scalar_piecewise_returns(
    *, contract: Mapping[str, Any], output_path: tuple[str, ...], indent: str
) -> str:
    paths = _array(contract.get("paths"), "finite scalar paths")
    if not paths:
        raise StageAInputError("finite scalar contract has no paths")
    lines: list[str] = []
    for index, path in enumerate(paths):
        value: Any = path
        for field in output_path:
            value = _object(value, f"finite scalar path field {field}").get(field)
        expression = _render_scalar_expression(value)
        guards = _array(path.get("guards"), "finite scalar path guards")
        condition = " && ".join(
            f"({_render_scalar_expression(guard)} != UINT32_C(0))"
            for guard in guards
        )
        if condition:
            lines.append(f"{indent}if ({condition}) return {expression};")
        elif index != len(paths) - 1:
            lines.append(f"{indent}return {expression};")
            break
        else:
            lines.append(f"{indent}return {expression};")
    if not any(line.lstrip().startswith("return ") for line in lines):
        final: Any = paths[-1]
        for field in output_path:
            final = _object(final, f"finite scalar path field {field}").get(field)
        lines.append(f"{indent}return {_render_scalar_expression(final)};")
    return "\n".join(lines)


def _render_scalar_expression(value: Any) -> str:
    if not isinstance(value, Mapping):
        raise StageAInputError("finite scalar C expression is malformed")
    op = value.get("op")
    if op == "const":
        constant = value.get("value")
        if not isinstance(constant, int):
            raise StageAInputError("finite scalar constant is malformed")
        return f"UINT32_C(0x{constant & _WORD_MASK:08x})"
    if op == "reg":
        if value.get("name") != "component_input":
            raise StageAInputError("finite scalar C expression has an unknown input")
        return "input"
    if op in {"true", "false"}:
        return "UINT32_C(1)" if op == "true" else "UINT32_C(0)"
    args = value.get("args")
    if not isinstance(args, list):
        raise StageAInputError(f"finite scalar operation {op!r} has no arguments")
    if op in {"add32", "sub32", "mul32", "xor32", "and32", "or32"}:
        operator = {
            "add32": "+",
            "sub32": "-",
            "mul32": "*",
            "xor32": "^",
            "and32": "&",
            "or32": "|",
        }[str(op)]
        if len(args) < 2:
            raise StageAInputError(f"finite scalar operation {op!r} is malformed")
        return "(" + f" {operator} ".join(_render_scalar_expression(arg) for arg in args) + ")"
    if op in {"ult32", "eq", "eq_bool", "xor_bool"} and len(args) == 2:
        left, right = (_render_scalar_expression(arg) for arg in args)
        operator = {"ult32": "<", "eq": "==", "eq_bool": "==", "xor_bool": "!="}[str(op)]
        return f"(({left} {operator} {right}) ? UINT32_C(1) : UINT32_C(0))"
    if op == "ite" and len(args) == 3:
        condition, when_true, when_false = (
            _render_scalar_expression(arg) for arg in args
        )
        return f"(({condition} != UINT32_C(0)) ? {when_true} : {when_false})"
    if op in {"not32", "neg32"} and len(args) == 1:
        operator = "~" if op == "not32" else "-"
        return f"({operator}{_render_scalar_expression(args[0])})"
    if op == "not" and len(args) == 1:
        child = _render_scalar_expression(args[0])
        return f"(({child} == UINT32_C(0)) ? UINT32_C(1) : UINT32_C(0))"
    if op in {"and_bool", "or_bool"} and args:
        operator = "&&" if op == "and_bool" else "||"
        rendered = f" {operator} ".join(
            f"({_render_scalar_expression(arg)} != UINT32_C(0))" for arg in args
        )
        return f"(({rendered}) ? UINT32_C(1) : UINT32_C(0))"
    if op == "parity" and len(args) == 2 and args[0] == 32:
        return f"semantic_parity({_render_scalar_expression(args[1])})"
    if op == "msb" and len(args) == 2 and args[0] == 32:
        return f"({_render_scalar_expression(args[1])} >> 31)"
    raise StageAInputError(
        f"finite scalar operation {op!r} is outside the reviewed C subset"
    )


def _install_finite_static_string_sources(
    *,
    root: Path,
    files: Mapping[str, Any],
    adapter_path: Path,
    adapter_symbol: str,
    contract: Mapping[str, Any],
    entry_rva: int,
) -> None:
    if contract.get("format") != FINITE_COMPONENT_CONTRACT_FORMAT:
        raise StageAInputError("finite component contract has an unsupported format")
    cases = _array(contract["result"].get("cases"), "finite result cases")
    values = {
        str(row["id"]): row
        for row in _array(contract["result"].get("values"), "finite result values")
    }
    header = """#ifndef SPAGHETTI_RECONSTRUCTED_IMPLEMENTATION_H
#define SPAGHETTI_RECONSTRUCTED_IMPLEMENTATION_H

#include <stdint.h>

const char *lookup_static_string(int32_t value);

#endif
"""
    source_cases = "\n".join(
        "    case UINT32_C(0x{input_bits:08x}): return {literal};".format(
            input_bits=int(row["input_bits"]),
            literal=_c_string_literal(str(values[str(row["value_id"])]["text"])),
        )
        for row in cases
    )
    portable = f"""#include "implementation.h"

#include <stddef.h>

const char *lookup_static_string(int32_t value) {{
  switch ((uint32_t)value) {{
{source_cases}
    default: return NULL;
  }}
}}
"""
    adapter_cases = "\n".join(
        "    case UINT32_C(0x{input_bits:08x}):\n"
        "      if (same_string(result, {literal}, UINT32_C({length}))) {{\n"
        "        *matched = 1U;\n"
        "        return UINT32_C(0x{guest_value:08x});\n"
        "      }}\n"
        "      return 0U;".format(
            input_bits=int(row["input_bits"]),
            literal=_c_string_literal(str(values[str(row["value_id"])]["text"])),
            length=int(values[str(row["value_id"])]["length_with_nul"]),
            guest_value=int(row["guest_value"]),
        )
        for row in cases
    )
    lines = [
        '#include "state-machine-runtime.h"',
        '#include "implementation.h"',
        "",
        "static uint32_t same_string(const char *left, const char *right, uint32_t size) {",
        "  uint32_t index;",
        "  if (left == (const char *)0 || right == (const char *)0) return left == right;",
        "  for (index = 0U; index < size; ++index) {",
        "    if (left[index] != right[index]) return 0U;",
        "    if (left[index] == '\\0') return index + 1U == size;",
        "  }",
        "  return 0U;",
        "}",
        "",
        "static uint32_t translate_result(uint32_t input, const char *result, uint32_t *matched) {",
        "  *matched = 0U;",
        "  switch (input) {",
        *adapter_cases.splitlines(),
        "    default:",
        "      if (result == (const char *)0) { *matched = 1U; return 0U; }",
        "      return 0U;",
        "  }",
        "}",
        "",
        f"stage_b_step_result {adapter_symbol}(stage_b_runtime *rt, stage_b_machine_state *state) {{",
        "  uint32_t fault = 0U, input, guest_value, matched, return_target;",
        "  const char *result;",
        "  input = rt->read(rt->context, state->esp + UINT32_C(4), UINT32_C(4), &fault);",
        "  if (fault) return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, state->original_rva, 0U };",
        "  return_target = rt->read(rt->context, state->esp, UINT32_C(4), &fault);",
        "  if (fault) return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, state->original_rva, 0U };",
        "  result = lookup_static_string((int32_t)input);",
        "  guest_value = translate_result(input, result, &matched);",
        f"  if (!matched) return (stage_b_step_result){{ STAGE_B_UNIMPLEMENTED, UINT32_C(0x{entry_rva:08x}), 0U }};",
        f"  state->original_rva = UINT32_C(0x{entry_rva:08x});",
        "  state->eax = guest_value;",
        "  state->edx = 0U;",
        "  state->esp += UINT32_C(4);",
        "  state->cf = 0U;",
        "  state->of = 0U;",
        "  state->pf = 1U;",
        "  state->sf = 0U;",
        "  state->zf = 1U;",
        *_machine_eflags_sync_lines("  "),
        "  return (stage_b_step_result){ STAGE_B_RETURN, 0U, return_target };",
        "}",
        "",
    ]
    (root / str(files["portable_header"])).write_text(header, encoding="ascii")
    (root / str(files["portable_source"])).write_text(portable, encoding="ascii")
    adapter_path.write_text("\n".join(lines), encoding="ascii")


def _install_bounded_string_length_sources(
    *,
    root: Path,
    files: Mapping[str, Any],
    adapter_path: Path,
    adapter_symbol: str,
    contract: Mapping[str, Any],
    entry_rva: int,
) -> None:
    validate_bounded_string_contract(contract)
    max_bytes = int(_object(contract.get("domain"), "bounded string domain")["max_bytes"])
    header = """#ifndef SPAGHETTI_RECONSTRUCTED_IMPLEMENTATION_H
#define SPAGHETTI_RECONSTRUCTED_IMPLEMENTATION_H

#include <stdint.h>

uint32_t bounded_string_length(const uint8_t *bytes, uint32_t limit);

#endif
"""
    portable = """#include "implementation.h"

uint32_t bounded_string_length(const uint8_t *bytes, uint32_t limit) {
  uint32_t index;
  for (index = 0U; index < limit; ++index) {
    if (bytes[index] == 0U)
      break;
  }
  return index;
}
"""
    lines = [
        '#include "state-machine-runtime.h"',
        '#include "implementation.h"',
        "",
        f"stage_b_step_result {adapter_symbol}(stage_b_runtime *rt, stage_b_machine_state *state) {{",
        f"  uint8_t bytes[UINT32_C({max_bytes})];",
        "  uint32_t fault = 0U, pointer, limit, length, index, return_target;",
        "  limit = rt->read(rt->context, state->esp + UINT32_C(8), UINT32_C(4), &fault);",
        "  if (fault) return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, state->original_rva, 0U };",
        f"  if (limit > UINT32_C({max_bytes}))",
        f"    return (stage_b_step_result){{ STAGE_B_UNIMPLEMENTED, UINT32_C(0x{entry_rva:08x}), 0U }};",
        "  pointer = rt->read(rt->context, state->esp + UINT32_C(4), UINT32_C(4), &fault);",
        "  if (fault) return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, state->original_rva, 0U };",
        "  rt->write(rt->context, state->esp - UINT32_C(4), UINT32_C(4), state->ebx, &fault);",
        "  if (fault) return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, state->original_rva, 0U };",
        "  for (index = 0U; index < limit; ++index) {",
        "    bytes[index] = (uint8_t)rt->read(rt->context, pointer + index, UINT32_C(1), &fault);",
        "    if (fault) return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, state->original_rva, 0U };",
        "    if (bytes[index] == 0U) break;",
        "  }",
        "  length = bounded_string_length(bytes, limit);",
        "  if (length > limit)",
        f"    return (stage_b_step_result){{ STAGE_B_UNIMPLEMENTED, UINT32_C(0x{entry_rva:08x}), 0U }};",
        "  return_target = rt->read(rt->context, state->esp, UINT32_C(4), &fault);",
        "  if (fault) return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, state->original_rva, 0U };",
        f"  state->original_rva = UINT32_C(0x{entry_rva:08x});",
        "  state->eax = length;",
        "  state->ecx = 0U;",
        "  state->edx = 0U;",
        "  state->esp += UINT32_C(4);",
        "  state->cf = 0U;",
        "  state->of = 0U;",
        "  state->pf = 1U;",
        "  state->sf = 0U;",
        "  state->zf = 1U;",
        *_machine_eflags_sync_lines("  "),
        "  return (stage_b_step_result){ STAGE_B_RETURN, 0U, return_target };",
        "}",
        "",
    ]
    (root / str(files["portable_header"])).write_text(header, encoding="ascii")
    (root / str(files["portable_source"])).write_text(portable, encoding="ascii")
    adapter_path.write_text("\n".join(lines), encoding="ascii")


def _install_bounded_pairwise_byte_compare_sources(
    *,
    root: Path,
    files: Mapping[str, Any],
    adapter_path: Path,
    adapter_symbol: str,
    contract: Mapping[str, Any],
    entry_rva: int,
) -> None:
    validate_bounded_pairwise_byte_contract(contract)
    domain = _object(contract.get("domain"), "bounded pairwise domain")
    max_bytes = int(domain["max_bytes"])
    dependency = _object(
        contract.get("component_call"), "bounded pairwise component call"
    )
    scalar_contract = _object(
        dependency.get("finite_component_contract"),
        "bounded pairwise scalar contract",
    )
    portable_normalize = _render_scalar_piecewise_returns(
        contract=scalar_contract,
        output_path=("output",),
        indent="  ",
    )
    adapter_normalize = _render_scalar_piecewise_returns(
        contract=scalar_contract,
        output_path=("output",),
        indent="  ",
    )
    needs_parity = "semantic_parity(" in portable_normalize
    parity_helper = (
        """static inline uint32_t semantic_parity(uint32_t value) {
  value ^= value >> 4;
  value &= UINT32_C(0x0f);
  return (UINT32_C(0x9669) >> value) & UINT32_C(1);
}

"""
        if needs_parity
        else ""
    )
    header = """#ifndef SPAGHETTI_RECONSTRUCTED_IMPLEMENTATION_H
#define SPAGHETTI_RECONSTRUCTED_IMPLEMENTATION_H

#include <stdint.h>

int32_t compare_pairwise_bytes(const uint8_t *left, const uint8_t *right);

#endif
"""
    portable = f"""#include "implementation.h"

{parity_helper}static uint32_t normalize_component_byte(uint32_t input) {{
{portable_normalize}
}}

int32_t compare_pairwise_bytes(const uint8_t *left, const uint8_t *right) {{
  if (left == right)
    return 0;
  for (;;) {{
    uint32_t left_value = normalize_component_byte(*left);
    uint32_t right_value = normalize_component_byte(*right);
    if (left_value == 0U || left_value != right_value)
      return (int32_t)(uint32_t)(left_value - right_value);
    ++left;
    ++right;
  }}
}}
"""
    adapter_lines = [
        '#include "state-machine-runtime.h"',
        '#include "implementation.h"',
        "",
    ]
    if needs_parity:
        adapter_lines.extend(parity_helper.rstrip().splitlines())
    adapter_lines.extend(
        [
            "static uint32_t adapter_normalize_component_byte(uint32_t input) {",
            adapter_normalize,
            "}",
            "",
            f"stage_b_step_result {adapter_symbol}(stage_b_runtime *rt, stage_b_machine_state *state) {{",
            f"  uint8_t left_bytes[UINT32_C({max_bytes})] = {{ 0U }};",
            f"  uint8_t right_bytes[UINT32_C({max_bytes})] = {{ 0U }};",
            "  uint32_t fault = 0U, left, right, index, decided = 0U, return_target;",
            "  int32_t ordering;",
            "  left = rt->read(rt->context, state->esp + UINT32_C(4), UINT32_C(4), &fault);",
            f"  if (fault) return (stage_b_step_result){{ STAGE_B_UNIMPLEMENTED, UINT32_C(0x{entry_rva:08x}), 0U }};",
            "  right = rt->read(rt->context, state->esp + UINT32_C(8), UINT32_C(4), &fault);",
            f"  if (fault) return (stage_b_step_result){{ STAGE_B_UNIMPLEMENTED, UINT32_C(0x{entry_rva:08x}), 0U }};",
            "  if (left == right) {",
            "    ordering = 0;",
            "    decided = 1U;",
            "  } else {",
            f"    for (index = 0U; index < UINT32_C({max_bytes}); ++index) {{",
            "      uint32_t left_value, right_value;",
            "      left_bytes[index] = (uint8_t)rt->read(rt->context, left + index, UINT32_C(1), &fault);",
            f"      if (fault) return (stage_b_step_result){{ STAGE_B_UNIMPLEMENTED, UINT32_C(0x{entry_rva:08x}), 0U }};",
            "      right_bytes[index] = (uint8_t)rt->read(rt->context, right + index, UINT32_C(1), &fault);",
            f"      if (fault) return (stage_b_step_result){{ STAGE_B_UNIMPLEMENTED, UINT32_C(0x{entry_rva:08x}), 0U }};",
            "      left_value = adapter_normalize_component_byte(left_bytes[index]);",
            "      right_value = adapter_normalize_component_byte(right_bytes[index]);",
            "      if (left_value == 0U || left_value != right_value) {",
            "        decided = 1U;",
            "        break;",
            "      }",
            "    }",
            f"    if (!decided) return (stage_b_step_result){{ STAGE_B_UNIMPLEMENTED, UINT32_C(0x{entry_rva:08x}), 0U }};",
            "    ordering = compare_pairwise_bytes(left_bytes, right_bytes);",
            "  }",
            "  return_target = rt->read(rt->context, state->esp, UINT32_C(4), &fault);",
            f"  if (fault) return (stage_b_step_result){{ STAGE_B_UNIMPLEMENTED, UINT32_C(0x{entry_rva:08x}), 0U }};",
            f"  state->original_rva = UINT32_C(0x{entry_rva:08x});",
            "  state->eax = (uint32_t)ordering;",
            "  state->ecx = 0U;",
            "  state->edx = 0U;",
            "  state->esp += UINT32_C(4);",
            "  state->cf = 0U;",
            "  state->of = 0U;",
            "  state->pf = 1U;",
            "  state->sf = 0U;",
            "  state->zf = 1U;",
            *_machine_eflags_sync_lines("  "),
            "  return (stage_b_step_result){ STAGE_B_RETURN, 0U, return_target };",
            "}",
            "",
        ]
    )
    (root / str(files["portable_header"])).write_text(header, encoding="ascii")
    (root / str(files["portable_source"])).write_text(portable, encoding="ascii")
    adapter_path.write_text("\n".join(adapter_lines), encoding="ascii")


def _machine_eflags_sync_lines(indent: str) -> list[str]:
    return [
        "#ifdef STAGE_B_MACHINE_STATE_HAS_EFLAGS",
        f"{indent}state->eflags =",
        f"{indent}    (state->eflags & ~UINT32_C(0x00000cd5)) |",
        f"{indent}    ((state->cf & 1U) << 0) | ((state->pf & 1U) << 2) |",
        f"{indent}    ((state->zf & 1U) << 6) | ((state->sf & 1U) << 7) |",
        f"{indent}    ((state->df & 1U) << 10) | ((state->of & 1U) << 11);",
        "#endif",
    ]


def _install_logical_profile_cases(
    *,
    root: Path,
    backend_workspace: Mapping[str, Any],
    profile: str,
    cluster: Mapping[str, Any],
    finite_contract: Mapping[str, Any] | None,
    bounded_string_contract: Mapping[str, Any] | None,
    bounded_pairwise_contract: Mapping[str, Any] | None,
) -> None:
    if profile == "finite_acyclic_scalar_v1":
        if finite_contract is None:
            raise StageAInputError("finite scalar profile omitted its derived contract")
        _install_finite_scalar_cases(
            root=root,
            backend_workspace=backend_workspace,
            cluster=cluster,
            contract=finite_contract,
        )
        return
    if profile == "finite_acyclic_static_string_lookup_v1":
        if finite_contract is None:
            raise StageAInputError("finite profile omitted its derived contract")
        _install_finite_static_string_cases(
            root=root,
            backend_workspace=backend_workspace,
            cluster=cluster,
            contract=finite_contract,
        )
        return
    if profile == "bounded_string_length_v1":
        if bounded_string_contract is None:
            raise StageAInputError("bounded string profile omitted its derived contract")
        _install_bounded_string_length_cases(
            root=root,
            backend_workspace=backend_workspace,
            cluster=cluster,
            contract=bounded_string_contract,
        )
        return
    if profile == "bounded_pairwise_byte_compare_v1":
        if bounded_pairwise_contract is None:
            raise StageAInputError(
                "bounded pairwise profile omitted its derived contract"
            )
        _install_bounded_pairwise_byte_compare_cases(
            root=root,
            backend_workspace=backend_workspace,
            cluster=cluster,
            contract=bounded_pairwise_contract,
        )
        return
    if profile != "bounded_range_rotation_v1":
        return
    files = _object(backend_workspace.get("files"), "backend workspace files")
    eax = 0x70002000
    edx = 0x70003000
    esp = 0x70001000
    flags = {"cf": 0, "zf": 1, "sf": 0, "of": 1, "pf": 0, "df": 1}
    windows = (
        (0, 0, 0),
        (0, 0, 3),
        (0, 3, 3),
        (0, 1, 3),
        (1, 3, 5),
        (2, 2, 6),
        (0, 3, 6),
        (0, 4, 8),
    )
    cases = []
    for index, (first, middle, end) in enumerate(windows):
        registers = {
            "eax": eax,
            "ebx": 0x11223344,
            "ecx": 0x55667788,
            "edx": edx,
            "esi": 0x12345678,
            "edi": 0x87654321,
            "ebp": 0x70004000,
            "esp": esp,
        }
        word_count = max(end, 1)
        word_bytes = b"".join(
            (0x10203040 + offset * 0x01010101 + index).to_bytes(4, "little")
            for offset in range(word_count)
        )
        cases.append(
            {
                "id": f"case:range-rotation-{index:02d}",
                "registers": registers,
                "flags": flags,
                "memory": [
                    {"address": eax, "bytes": word_bytes.hex()},
                    {"address": edx, "bytes": end.to_bytes(4, "little").hex()},
                    {
                        "address": edx + 28,
                        "bytes": first.to_bytes(4, "little").hex(),
                    },
                    {
                        "address": edx + 32,
                        "bytes": middle.to_bytes(4, "little").hex(),
                    },
                    {"address": esp, "bytes": "78563412"},
                ],
                "external_response_seed": f"rotation-{index:02d}",
            }
        )
    payload = {
        "format": "stage-b-reconstruction-cases-v1",
        "cluster_id": cluster["id"],
        "entry_unit_id": cluster["entry_unit_id"],
        "entry_rva": cluster["entry_rva"],
        "cases": cases,
    }
    payload["cases_sha256"] = _canonical_sha256(payload)
    write_json(root / str(files["cases"]), payload)


def _install_finite_scalar_cases(
    *,
    root: Path,
    backend_workspace: Mapping[str, Any],
    cluster: Mapping[str, Any],
    contract: Mapping[str, Any],
) -> None:
    if contract.get("profile") != "finite_acyclic_scalar_v1":
        raise StageAInputError("finite scalar cases require a scalar contract")
    files = _object(backend_workspace.get("files"), "backend workspace files")
    probes = {
        *range(256),
        0x7FFFFFFF,
        0x80000000,
        0xFFFFFFFE,
        0xFFFFFFFF,
    }

    def collect_constants(value: Any) -> None:
        if not isinstance(value, Mapping):
            return
        if value.get("op") == "const" and isinstance(value.get("value"), int):
            constant = int(value["value"]) & _WORD_MASK
            probes.update(
                {(constant - 1) & _WORD_MASK, constant, (constant + 1) & _WORD_MASK}
            )
        for child in value.get("args", []):
            collect_constants(child)

    for path in _array(contract.get("paths"), "finite scalar paths"):
        collect_constants(path.get("output"))
        for guard in _array(path.get("guards"), "finite scalar path guards"):
            collect_constants(guard)
    esp = 0x70001000
    rows = []
    for index, input_bits in enumerate(sorted(probes)):
        rows.append(
            {
                "id": f"case:finite-scalar-{index:03d}",
                "registers": {
                    "eax": 0x10203040,
                    "ebx": 0x11223344,
                    "ecx": 0x55667788,
                    "edx": 0x89ABCDEF,
                    "esi": 0x12345678,
                    "edi": 0x87654321,
                    "ebp": 0x70004000,
                    "esp": esp,
                },
                "flags": {
                    "cf": index & 1,
                    "zf": (index >> 1) & 1,
                    "sf": (index >> 2) & 1,
                    "of": (index >> 3) & 1,
                    "pf": (index >> 4) & 1,
                    "df": (index >> 5) & 1,
                },
                "memory": [
                    {"address": esp, "bytes": "78563412"},
                    {
                        "address": esp + 4,
                        "bytes": input_bits.to_bytes(4, "little").hex(),
                    },
                ],
                "external_response_seed": f"finite-scalar-{input_bits:08x}",
            }
        )
    payload = {
        "format": "stage-b-reconstruction-cases-v1",
        "cluster_id": cluster["id"],
        "entry_unit_id": cluster["entry_unit_id"],
        "entry_rva": cluster["entry_rva"],
        "cases": rows,
    }
    payload["cases_sha256"] = _canonical_sha256(payload)
    write_json(root / str(files["cases"]), payload)


def _install_finite_static_string_cases(
    *,
    root: Path,
    backend_workspace: Mapping[str, Any],
    cluster: Mapping[str, Any],
    contract: Mapping[str, Any],
) -> None:
    files = _object(backend_workspace.get("files"), "backend workspace files")
    cases = _array(contract["result"].get("cases"), "finite result cases")
    mapped = {int(row["input_bits"]) for row in cases}
    probes = {0, 1, _WORD_MASK, 0x80000000}
    for value in mapped:
        probes.add((value - 1) & _WORD_MASK)
        probes.add((value + 1) & _WORD_MASK)
    inputs = sorted(mapped | (probes - mapped))
    esp = 0x70001000
    table_memory = [
        {
            "address": int(row["guest_address"]),
            "bytes": str(row["bytes_hex"]),
        }
        for row in _array(contract.get("control_tables"), "finite control tables")
    ]
    rows = []
    for index, input_bits in enumerate(inputs):
        rows.append(
            {
                "id": f"case:finite-static-string-{index:03d}",
                "registers": {
                    "eax": 0x10203040,
                    "ebx": 0x11223344,
                    "ecx": 0x55667788,
                    "edx": 0x89ABCDEF,
                    "esi": 0x12345678,
                    "edi": 0x87654321,
                    "ebp": 0x70004000,
                    "esp": esp,
                },
                "flags": {"cf": 1, "zf": 0, "sf": 1, "of": 1, "pf": 0, "df": 1},
                "memory": [
                    {"address": esp, "bytes": "78563412"},
                    {"address": esp + 4, "bytes": input_bits.to_bytes(4, "little").hex()},
                    *copy.deepcopy(table_memory),
                ],
                "external_response_seed": f"finite-static-string-{input_bits:08x}",
            }
        )
    payload = {
        "format": "stage-b-reconstruction-cases-v1",
        "cluster_id": cluster["id"],
        "entry_unit_id": cluster["entry_unit_id"],
        "entry_rva": cluster["entry_rva"],
        "address_space": copy.deepcopy(contract["address_space"]),
        "cases": rows,
    }
    payload["cases_sha256"] = _canonical_sha256(payload)
    write_json(root / str(files["cases"]), payload)


def _install_bounded_string_length_cases(
    *,
    root: Path,
    backend_workspace: Mapping[str, Any],
    cluster: Mapping[str, Any],
    contract: Mapping[str, Any],
) -> None:
    validate_bounded_string_contract(contract)
    files = _object(backend_workspace.get("files"), "backend workspace files")
    max_bytes = int(_object(contract.get("domain"), "bounded string domain")["max_bytes"])
    esp = 0x70001000
    pointer = 0x70002000
    rows = []
    for limit in range(max_bytes + 1):
        for zero_index in range(limit + 1):
            data = bytearray(
                ((index * 73 + limit * 29 + zero_index * 11) % 255) + 1
                for index in range(max(limit, 1))
            )
            label = "none"
            if zero_index < limit:
                data[zero_index] = 0
                label = f"{zero_index:02d}"
            rows.append(
                {
                    "id": f"case:bounded-strnlen-{limit:02d}-{label}",
                    "registers": {
                        "eax": 0x10203040,
                        "ebx": 0x11223344,
                        "ecx": 0x55667788,
                        "edx": 0x89ABCDEF,
                        "esi": 0x12345678,
                        "edi": 0x87654321,
                        "ebp": 0x70004000,
                        "esp": esp,
                    },
                    "flags": {
                        "cf": 1,
                        "zf": 0,
                        "sf": 1,
                        "of": 1,
                        "pf": 0,
                        "df": 1,
                    },
                    "memory": [
                        {"address": esp, "bytes": "78563412"},
                        {"address": esp + 4, "bytes": pointer.to_bytes(4, "little").hex()},
                        {"address": esp + 8, "bytes": limit.to_bytes(4, "little").hex()},
                        {"address": pointer, "bytes": bytes(data).hex()},
                    ],
                    "external_response_seed": f"bounded-strnlen-{limit:02d}-{label}",
                }
            )
    payload = {
        "format": "stage-b-reconstruction-cases-v1",
        "cluster_id": cluster["id"],
        "entry_unit_id": cluster["entry_unit_id"],
        "entry_rva": cluster["entry_rva"],
        "cases": rows,
    }
    payload["cases_sha256"] = _canonical_sha256(payload)
    write_json(root / str(files["cases"]), payload)


def _install_bounded_pairwise_byte_compare_cases(
    *,
    root: Path,
    backend_workspace: Mapping[str, Any],
    cluster: Mapping[str, Any],
    contract: Mapping[str, Any],
) -> None:
    validate_bounded_pairwise_byte_contract(contract)
    files = _object(backend_workspace.get("files"), "backend workspace files")
    max_bytes = int(_object(contract.get("domain"), "bounded pairwise domain")["max_bytes"])
    esp = 0x70001000
    left_pointer = 0x70002000
    right_pointer = 0x70003000
    probes: list[tuple[str, bytes | None, bytes | None, bool]] = [
        ("same-pointer", None, None, True),
        ("empty", b"\0", b"\0", False),
        ("empty-left", b"\0", b"a\0", False),
        ("empty-right", b"a\0", b"\0", False),
        ("case-equal", b"a\0", b"A\0", False),
        ("word-case-equal", b"abc\0", b"AbC\0", False),
        ("less", b"abc\0", b"abd\0", False),
        ("greater", b"abd\0", b"abc\0", False),
        ("high-equal", b"\x80\0", b"\x80\0", False),
        ("high-less", b"\x80\0", b"\x81\0", False),
    ]
    for index in range(max_bytes):
        prefix = b"a" * index
        probes.append((f"mismatch-{index:02d}", prefix + b"b\0", prefix + b"c\0", False))
        probes.append((f"left-zero-{index:02d}", prefix + b"\0", prefix + b"a\0", False))
    probes.append(
        (
            "fallback-after-bound",
            b"a" * max_bytes + b"b\0",
            b"a" * max_bytes + b"c\0",
            False,
        )
    )

    rows = []
    for index, (label, left_bytes, right_bytes, same_pointer) in enumerate(probes):
        left = left_pointer + index * 0x100
        right = left if same_pointer else right_pointer + index * 0x100
        memory = [
            {"address": esp, "bytes": "78563412"},
            {"address": esp + 4, "bytes": left.to_bytes(4, "little").hex()},
            {"address": esp + 8, "bytes": right.to_bytes(4, "little").hex()},
        ]
        if left_bytes is not None:
            memory.append({"address": left, "bytes": left_bytes.hex()})
        if right_bytes is not None and right != left:
            memory.append({"address": right, "bytes": right_bytes.hex()})
        rows.append(
            {
                "id": f"case:bounded-pairwise-{label}",
                "registers": {
                    "eax": 0x10203040,
                    "ebx": 0x11223344,
                    "ecx": 0x55667788,
                    "edx": 0x89ABCDEF,
                    "esi": 0x12345678,
                    "edi": 0x87654321,
                    "ebp": 0x70004000,
                    "esp": esp,
                },
                "flags": {
                    "cf": index & 1,
                    "zf": (index >> 1) & 1,
                    "sf": (index >> 2) & 1,
                    "of": (index >> 3) & 1,
                    "pf": (index >> 4) & 1,
                    "df": (index >> 5) & 1,
                },
                "memory": memory,
                "external_response_seed": f"bounded-pairwise-{label}",
            }
        )
    payload = {
        "format": "stage-b-reconstruction-cases-v1",
        "cluster_id": cluster["id"],
        "entry_unit_id": cluster["entry_unit_id"],
        "entry_rva": cluster["entry_rva"],
        "cases": rows,
    }
    payload["cases_sha256"] = _canonical_sha256(payload)
    write_json(root / str(files["cases"]), payload)


def _constant_compare_descriptor(logical: Mapping[str, Any]) -> dict[str, Any]:
    parameters = [
        item for item in logical.get("parameters", []) if isinstance(item, Mapping)
    ]
    controls = [
        item
        for item in logical.get("results", [])
        if isinstance(item, Mapping) and item.get("kind") == "control"
    ]
    if len(parameters) != 1 or len(controls) != 1:
        raise StageAInputError(
            "constant comparison profile requires one parameter and one control result"
        )
    source = _object(parameters[0].get("machine_source"), "comparison machine source")
    if source.get("kind") != "expression":
        raise StageAInputError(
            "constant comparison parameter must bind a normalized expression"
        )
    source_expression = _object(source.get("expression"), "comparison source expression")
    register, mask, width = _masked_register(source_expression)
    control = _object(controls[0].get("control"), "constant comparison control")
    condition = _object(control.get("condition"), "constant comparison condition")
    taken_on_equal = True
    if condition.get("op") == "not":
        args = condition.get("args")
        if not isinstance(args, list) or len(args) != 1 or not isinstance(args[0], Mapping):
            raise StageAInputError("constant comparison has malformed negation")
        condition = args[0]
        taken_on_equal = False
    if condition.get("op") != "eq":
        raise StageAInputError("constant comparison control is not equality-based")
    args = condition.get("args")
    if not isinstance(args, list) or len(args) != 2:
        raise StageAInputError("constant comparison equality is malformed")
    if _constant_value(args[0]) == 0:
        difference = args[1]
    elif _constant_value(args[1]) == 0:
        difference = args[0]
    else:
        raise StageAInputError("constant comparison equality is not against zero")
    if width < 32:
        difference_mapping = _object(difference, "masked comparison difference")
        if difference_mapping.get("op") != "and32":
            raise StageAInputError("partial-width comparison does not mask its result")
        difference_args = difference_mapping.get("args")
        if not isinstance(difference_args, list) or len(difference_args) != 2:
            raise StageAInputError("masked comparison difference is malformed")
        if _constant_value(difference_args[0]) == mask:
            difference = difference_args[1]
        elif _constant_value(difference_args[1]) == mask:
            difference = difference_args[0]
        else:
            raise StageAInputError("comparison result mask does not match its input")
    difference_mapping = _object(difference, "comparison difference")
    difference_args = difference_mapping.get("args")
    if difference_mapping.get("op") != "sub32" or not isinstance(
        difference_args, list
    ) or len(difference_args) != 2:
        raise StageAInputError("constant comparison is not a subtraction")
    if difference_args[0] != source_expression:
        raise StageAInputError("comparison source differs from the logical parameter")
    constant = _constant_value(difference_args[1])
    if constant is None or constant < 0 or constant > mask:
        raise StageAInputError("comparison constant is outside the operand width")
    routes = control.get("routes")
    if not isinstance(routes, list) or len(routes) != 2:
        raise StageAInputError("constant comparison requires two checked routes")
    targets: dict[bool, int] = {}
    for route in routes:
        if (
            not isinstance(route, Mapping)
            or not isinstance(route.get("when"), bool)
            or not isinstance(route.get("target_rva"), int)
        ):
            raise StageAInputError("constant comparison route is malformed")
        targets[bool(route["when"])] = int(route["target_rva"])
    if set(targets) != {False, True}:
        raise StageAInputError("constant comparison routes are not exhaustive")
    return {
        "register": register,
        "mask": mask,
        "width": width,
        "constant": constant,
        "taken_on_equal": taken_on_equal,
        "true_target_rva": targets[True],
        "false_target_rva": targets[False],
    }


def _range_rotation_descriptor(logical: Mapping[str, Any]) -> dict[str, Any]:
    parameters = {
        str(item.get("id")): item
        for item in logical.get("parameters", [])
        if isinstance(item, Mapping) and isinstance(item.get("id"), str)
    }
    if set(parameters) != {"words", "window"}:
        raise StageAInputError(
            "range rotation profile requires words and window parameters"
        )
    expected_registers = {"words": "eax", "window": "edx"}
    for parameter_id, register in expected_registers.items():
        source = _object(
            parameters[parameter_id].get("machine_source"),
            f"range rotation {parameter_id} source",
        )
        if (
            source.get("kind") != "register"
            or source.get("name") != register
            or source.get("width") != 32
        ):
            raise StageAInputError(
                f"range rotation {parameter_id} must bind 32-bit {register}"
            )
    controls = [
        item
        for item in logical.get("results", [])
        if isinstance(item, Mapping) and item.get("kind") == "control"
    ]
    if len(controls) != 1 or controls[0].get("control", {}).get(
        "outcome_kind"
    ) != "return":
        raise StageAInputError("range rotation profile requires one return result")
    object_ids = {
        str(item.get("id"))
        for item in logical.get("objects", [])
        if isinstance(item, Mapping) and isinstance(item.get("id"), str)
    }
    required_objects = {
        "window_last_nonopt",
        "window_first_nonopt",
        "window_optind",
        "word_array_left_a",
        "word_array_right_a",
        "word_array_left_b",
        "word_array_right_b",
    }
    if object_ids != required_objects:
        raise StageAInputError("range rotation logical objects are incomplete")
    claim_ids = {
        str(item.get("id"))
        for item in logical.get("claims", [])
        if isinstance(item, Mapping) and isinstance(item.get("id"), str)
    }
    required_claims = {"ordered-window", "left-rotation", "window-update"}
    if not required_claims.issubset(claim_ids):
        raise StageAInputError("range rotation logical claims are incomplete")
    return {
        "word_register": "eax",
        "window_register": "edx",
        "claims": sorted(required_claims),
        "observable_memory": [
            {
                "semantic_expression": {
                    "op": "reg",
                    "name": "eax",
                    "width": 32,
                },
                "width": _BOUNDED_RANGE_ROTATION_WORDS * 4,
                "access": "read_write",
            },
            {
                "semantic_expression": {
                    "op": "reg",
                    "name": "edx",
                    "width": 32,
                },
                "width": 36,
                "access": "read_write",
            },
        ],
    }


def _masked_register(expression: Mapping[str, Any]) -> tuple[str, int, int]:
    if expression.get("op") == "reg":
        name = expression.get("name")
        width = expression.get("width")
        if isinstance(name, str) and width == 32:
            return name, 0xFFFFFFFF, 32
    if expression.get("op") != "and32":
        raise StageAInputError("comparison source is not a masked register")
    args = expression.get("args")
    if not isinstance(args, list) or len(args) != 2:
        raise StageAInputError("masked comparison source is malformed")
    constant = _constant_value(args[0])
    register = args[1]
    if constant is None:
        constant = _constant_value(args[1])
        register = args[0]
    if not isinstance(register, Mapping) or register.get("op") != "reg":
        raise StageAInputError("comparison source mask is not applied to a register")
    widths = {0xFF: 8, 0xFFFF: 16, 0xFFFFFFFF: 32}
    if constant not in widths or not isinstance(register.get("name"), str):
        raise StageAInputError("comparison source has an unsupported width mask")
    return str(register["name"]), int(constant), widths[int(constant)]


def _constant_value(value: Any) -> int | None:
    if (
        isinstance(value, Mapping)
        and value.get("op") == "const"
        and isinstance(value.get("value"), int)
        and not isinstance(value.get("value"), bool)
    ):
        return int(value["value"])
    return None


def _namespace_portable_function(
    *,
    root: Path,
    backend_workspace: Mapping[str, Any],
    entry_rva: int,
    preferred_symbol: str | None = None,
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
        "classify_value",
        "rotate_words",
        "bounded_string_length",
        "compare_pairwise_bytes",
        "compute_scalar",
        "lookup_static_string",
        "run_service_operation",
        "initialize_word",
        "reconstruct_region",
    )
    matches = (
        [preferred_symbol]
        if preferred_symbol is not None
        and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", preferred_symbol)
        and re.search(rf"\b{re.escape(preferred_symbol)}\b", header)
        else [name for name in candidates if re.search(rf"\b{name}\b", header)]
    )
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
    namespaced = re.fullmatch(r"component_[0-9a-fA-F]{8}_(.+)", expected)
    source_symbol = namespaced.group(1) if namespaced is not None else expected
    matches = (
        [source_symbol]
        if source_symbol != expected
        and re.search(rf"\b{re.escape(source_symbol)}\b", text)
        else []
    )
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
    if not matches:
        boundary = _object(component.get("machine_boundary"), "component machine boundary")
        entry_units = {
            str(item["unit_id"])
            for item in _array(boundary.get("entries"), "component machine entries")
            if item.get("rva") == entry_rva and isinstance(item.get("unit_id"), str)
        }
        if len(entry_units) == 1:
            entry_unit_id = next(iter(entry_units))
            matches = [
                item
                for item in clusters
                if entry_unit_id
                in {
                    str(value)
                    for value in _array(item.get("unit_ids", []), "cluster unit IDs")
                }
            ]
    if len(matches) != 1:
        raise StageAInputError(
            f"component {component.get('id')} has {len(matches)} reconstruction clusters"
        )
    return matches[0]


def _needs_component_execution_cluster(
    *,
    has_profile: bool,
    component_unit_ids: set[str],
    cluster_unit_ids: set[str],
    has_dependencies: bool,
) -> bool:
    """Return whether checked component semantics must replace discovery data."""

    return (
        has_profile
        or component_unit_ids != cluster_unit_ids
        or has_dependencies
    )


def _component_execution_cluster(
    *,
    selected_cluster: Mapping[str, Any],
    component: Mapping[str, Any],
    units: Sequence[Mapping[str, Any]],
    observable_memory: Sequence[Mapping[str, Any]],
    component_dependencies: Sequence[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    """Materialize a regional execution boundary from component membership.

    Reconstruction-plan clusters are local coarsening hints and can be smaller
    than a semantic component.  Candidate-only integration must execute every
    declared component unit before comparing the replacement's boundary.
    """

    expected_ids = {
        str(value) for value in component["membership"]["resolved_unit_ids"]
    }
    by_id = {str(unit.get("id")): unit for unit in units}
    if len(by_id) != len(units):
        raise StageAInputError("component execution slice has duplicate unit IDs")
    if set(by_id) != expected_ids:
        raise StageAInputError(
            "component execution slice does not match resolved component membership"
        )
    spans = []
    for unit_id in expected_ids:
        source = _object(by_id[unit_id].get("source"), f"source for {unit_id}")
        original = _object(source.get("original"), f"original span for {unit_id}")
        start, end = original.get("rva_start"), original.get("rva_end")
        if not isinstance(start, int) or not isinstance(end, int) or end <= start:
            raise StageAInputError(f"component unit has an invalid RVA span: {unit_id}")
        spans.append({"start": start, "end": end})
    spans.sort(key=lambda item: (item["start"], item["end"]))
    boundary = _object(component.get("machine_boundary"), "component machine boundary")
    exits = _array(boundary.get("exits"), "component machine exits")
    selected_call_keys = {
        (str(callsite["source_unit_id"]), int(dependency["target_rva"]))
        for dependency in component_dependencies
        for callsite in _array(
            dependency.get("callsites", []), "component dependency callsites"
        )
    }
    controls_by_source: dict[tuple[str, str], dict[str, Any]] = {}
    for raw in exits:
        item = _object(raw, "component machine exit")
        boundary_kind = str(item.get("kind"))
        source_unit_id = str(item.get("source_unit_id"))
        source_unit = by_id.get(source_unit_id)
        if source_unit is None:
            raise StageAInputError(
                f"component exit references a non-member source: {source_unit_id}"
            )
        if boundary_kind == "internal_call" and (
            source_unit_id,
            int(item.get("target_rva", -1)),
        ) in selected_call_keys:
            continue
        if boundary_kind == "return":
            kind = "return"
            target_rva = None
            target_unit_id = None
        elif boundary_kind == "direct_control":
            outcome = _object(
                source_unit.get("semantics", {}).get("outcome"),
                f"component exit outcome for {source_unit_id}",
            )
            kind = str(outcome.get("kind"))
            if kind not in {"fallthrough", "jump", "branch"}:
                raise StageAInputError(
                    "component direct-control exit has unsupported semantic kind: "
                    f"{kind}"
                )
            target_rva = item.get("target_rva")
            target_unit_id = item.get("target_unit_id")
            if not isinstance(target_rva, int) or not isinstance(
                target_unit_id, str
            ):
                raise StageAInputError("component direct-control exit is malformed")
            semantic_targets = {
                int(value)
                for key in (
                    "target_rva",
                    "true_target_rva",
                    "false_target_rva",
                )
                if isinstance((value := outcome.get(key)), int)
            }
            if target_rva not in semantic_targets:
                raise StageAInputError(
                    "component direct-control exit disagrees with machine semantics"
                )
        else:
            raise StageAInputError(
                f"component execution cluster has unsupported exit kind: {boundary_kind}"
            )
        key = (source_unit_id, kind)
        control = controls_by_source.setdefault(
            key,
            {
                "kind": kind,
                "source_unit_id": source_unit_id,
                "target_rvas": [],
                "target_unit_ids": [],
            },
        )
        if target_rva is not None:
            control["target_rvas"].append(target_rva)
            control["target_unit_ids"].append(target_unit_id)
    controls = sorted(
        controls_by_source.values(),
        key=lambda item: (item["source_unit_id"], item["kind"]),
    )
    for control in controls:
        control["target_rvas"] = sorted(set(control["target_rvas"]))
        control["target_unit_ids"] = sorted(set(control["target_unit_ids"]))
    if not controls:
        raise StageAInputError("component execution cluster has no machine exits")
    entry_rva = _component_entry_rva(component)
    entry_units = {
        str(item["unit_id"])
        for item in _array(boundary.get("entries"), "component machine entries")
        if item.get("rva") == entry_rva
        and item.get("kind") != "internal_call"
        and isinstance(item.get("unit_id"), str)
    }
    if len(entry_units) != 1:
        raise StageAInputError(
            "component execution cluster requires one external entry unit"
        )
    external_events = _normalized_component_call_plan(
        component=component,
        component_dependencies=component_dependencies,
    )["external_trace"]
    result = copy.deepcopy(dict(selected_cluster))
    result.update(
        {
            "id": "component-cluster:" + str(component["id"]),
            "category": "semantic_component",
            "template": str(selected_cluster.get("template") or "manual_contract"),
            "entry_rva": entry_rva,
            "entry_unit_id": next(iter(entry_units)),
            "unit_ids": sorted(
                expected_ids,
                key=lambda unit_id: (
                    int(by_id[unit_id]["source"]["original"]["rva_start"]),
                    unit_id,
                ),
            ),
            "rva_spans": spans,
            "control": controls,
            "external_events": external_events,
            "memory": copy.deepcopy(list(observable_memory)),
            "composition": {
                "kind": "checked_semantic_component_boundary",
                "status": "checked_by_component_interface",
                "component_id": str(component["id"]),
                "unit_ids": sorted(expected_ids),
            },
            "component_execution_boundary": {
                "status": "checked",
                "component_sha256": str(component["component_sha256"]),
            },
        }
    )
    result.pop("contract_sha256", None)
    result["contract_sha256"] = _canonical_sha256(result)
    return result


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


def _component_call_dependency_status(
    root: Path, refinement: Mapping[str, Any]
) -> str:
    plan = _object(
        refinement.get(
            "component_call_dependencies",
            {
                "status": "not_applicable",
                "calls": [],
                "remaining_events": [],
                "remaining_exits": [],
            },
        ),
        "component call dependency plan",
    )
    calls = _array(plan.get("calls"), "component call dependencies")
    if not calls:
        return "not_applicable" if plan.get("status") == "not_applicable" else "stale"
    if plan.get("status") != "checked":
        return "stale"
    try:
        for raw in calls:
            dependency = _object(raw, "component call dependency")
            expected_binding = dependency.get("binding_sha256")
            binding_core = copy.deepcopy(dict(dependency))
            binding_core.pop("binding_sha256", None)
            if expected_binding != _canonical_sha256(binding_core):
                return "stale"
            evidence = _object(
                dependency.get("evidence"), "component dependency evidence"
            )
            loaded: dict[str, Mapping[str, Any]] = {}
            for kind in ("workspace", "refinement", "qualification"):
                descriptor = _object(
                    evidence.get(kind), f"component dependency {kind} evidence"
                )
                relative = Path(str(descriptor.get("path")))
                if relative.is_absolute() or ".." in relative.parts:
                    return "stale"
                path = root / relative
                if not path.is_file() or sha256_file(path) != descriptor.get("sha256"):
                    return "stale"
                loaded[kind] = _read_object(
                    path, f"component dependency copied {kind}"
                )
            child_workspace = loaded["workspace"]
            child_refinement = loaded["refinement"]
            child_qualification = loaded["qualification"]
            _require_format(
                child_workspace,
                COMPONENT_WORKSPACE_FORMAT,
                "component dependency workspace",
            )
            _require_format(
                child_refinement,
                COMPONENT_REFINEMENT_FORMAT,
                "component dependency refinement",
            )
            _require_format(
                child_qualification,
                COMPONENT_QUALIFICATION_FORMAT,
                "component dependency qualification",
            )
            for payload, hash_field in (
                (child_workspace, "workspace_sha256"),
                (child_refinement, "refinement_sha256"),
                (child_qualification, "qualification_sha256"),
            ):
                payload_core = copy.deepcopy(dict(payload))
                expected = payload_core.pop(hash_field, None)
                if expected != _canonical_sha256(payload_core):
                    return "stale"
            target_component_id = dependency.get("target_component_id")
            if (
                child_workspace.get("component_id") != target_component_id
                or child_refinement.get("component", {}).get("id")
                != target_component_id
                or child_qualification.get("component_id") != target_component_id
                or child_workspace.get("bindings", {}).get("refinement_sha256")
                != child_refinement.get("refinement_sha256")
                or child_qualification.get("bindings", {}).get(
                    "component_workspace_sha256"
                )
                != child_workspace.get("workspace_sha256")
                or child_qualification.get("bindings", {}).get("refinement_sha256")
                != child_refinement.get("refinement_sha256")
                or child_qualification.get("qualification_sha256")
                != dependency.get("qualification_sha256")
                or child_refinement.get("refinement_sha256")
                != dependency.get("refinement_sha256")
                or child_qualification.get("status") != "qualified"
                or child_qualification.get("activation", {}).get("authorized")
                is not True
                or child_qualification.get("activation", {}).get("domain", {}).get(
                    "kind"
                )
                != "total"
            ):
                return "stale"
            child_contract = _component_proof_contract_from_refinement(
                child_refinement
            )
            if child_contract != dependency.get("component_contract"):
                return "stale"
    except (KeyError, TypeError, ValueError, StageAInputError):
        return "stale"
    return "checked"


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


def _select_machine_units(
    available: Sequence[Mapping[str, Any]],
    unit_ids: Sequence[str],
    description: str,
) -> list[Mapping[str, Any]]:
    """Select exact component members without exposing retained support units."""

    if len(set(unit_ids)) != len(unit_ids):
        raise StageAInputError("component membership contains duplicate machine unit IDs")
    by_id: dict[str, Mapping[str, Any]] = {}
    for unit in available:
        unit_id = str(unit.get("id"))
        if unit_id in by_id:
            raise StageAInputError(f"{description} contain duplicate unit ID: {unit_id}")
        by_id[unit_id] = unit
    missing = [unit_id for unit_id in unit_ids if unit_id not in by_id]
    if missing:
        raise StageAInputError(
            f"{description} omit declared component unit IDs: {missing}"
        )
    return [by_id[unit_id] for unit_id in unit_ids]


def _load_checked_interface_refinement(
    path: Path,
    *,
    component: Mapping[str, Any],
    machine_ir_sha256: str,
) -> dict[str, Any]:
    payload = _read_object(path, "component interface refinement")
    _require_format(
        payload,
        COMPONENT_INTERFACE_REFINEMENT_FORMAT,
        "component interface refinement",
    )
    expected = payload.get("refinement_sha256")
    core = copy.deepcopy(payload)
    core.pop("refinement_sha256", None)
    if expected != _canonical_sha256(core):
        raise StageAInputError("component interface refinement self-hash is stale")
    if (
        payload.get("status") != "checked"
        or payload.get("executes_original_binary") is not False
        or payload.get("issues") not in (None, [])
    ):
        raise StageAInputError("component logical interface is not checked")
    if not isinstance(payload.get("logical_interface"), Mapping):
        raise StageAInputError(
            "component interface refinement omits its checked logical interface"
        )
    component_binding = _object(
        payload.get("component"), "component interface component binding"
    )
    if (
        component_binding.get("id") != component.get("id")
        or component_binding.get("sha256") != component.get("component_sha256")
    ):
        raise StageAInputError("component interface/component binding is stale")
    bindings = _object(
        payload.get("bindings"), "component interface input bindings"
    )
    if bindings.get("machine_ir_sha256") != machine_ir_sha256:
        raise StageAInputError("component interface input binding is stale")
    return payload


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
    bindings = _object(payload.get("bindings"), "component slice bindings")
    if bindings.get("catalog_binding_kind") == "component_self_hash":
        component_core = copy.deepcopy(dict(component))
        component_sha256 = component_core.pop("component_sha256", None)
        if component_sha256 != _canonical_sha256(component_core):
            raise StageAInputError("sliced component self-hash is stale")
        if bindings.get("catalog_artifact_sha256") != component_sha256:
            raise StageAInputError("component slice local catalog binding is stale")
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


def _load_checked_component_dependencies(
    *, component: Mapping[str, Any], dependency_roots: Sequence[Path]
) -> list[_CheckedComponentDependency]:
    declarations = [
        _object(item, "selected component dependency")
        for item in _array(component.get("component_calls", []), "component calls")
    ]
    roots = [Path(value) for value in dependency_roots]
    if len(roots) != len(set(roots)):
        raise StageAInputError("component dependency roots are duplicated")
    if not declarations:
        if roots:
            raise StageAInputError(
                "component dependency inputs were supplied without selected calls"
            )
        return []

    by_component: dict[str, tuple[Path, Mapping[str, Any]]] = {}
    for root in roots:
        workspace = _load_component_workspace(root)
        component_id = str(workspace.get("component_id"))
        if component_id in by_component:
            raise StageAInputError(
                f"duplicate qualified dependency for component {component_id}"
            )
        by_component[component_id] = (root, workspace)
    declared_ids = {str(item.get("target_component_id")) for item in declarations}
    if set(by_component) != declared_ids:
        raise StageAInputError(
            "qualified dependency inputs do not exactly match selected component calls"
        )

    checked: list[_CheckedComponentDependency] = []
    for declaration in sorted(
        declarations,
        key=lambda item: (str(item.get("target_component_id")), int(item.get("target_rva", -1))),
    ):
        target_component_id = declaration.get("target_component_id")
        target_rva = declaration.get("target_rva")
        target_unit_id = declaration.get("target_unit_id")
        dependency_sha256 = declaration.get("dependency_sha256")
        if (
            not isinstance(target_component_id, str)
            or not target_component_id
            or not isinstance(target_rva, int)
            or not isinstance(target_unit_id, str)
            or not target_unit_id
            or not isinstance(dependency_sha256, str)
            or not dependency_sha256
        ):
            raise StageAInputError("selected component dependency is malformed")
        root, workspace = by_component[target_component_id]
        refinement = _load_bound_refinement(root, workspace)
        qualification_path = root / "component-qualification.json"
        qualification = _read_object(
            qualification_path, "component dependency qualification"
        )
        _require_format(
            qualification,
            COMPONENT_QUALIFICATION_FORMAT,
            "component dependency qualification",
        )
        qualification_core = copy.deepcopy(qualification)
        observed_qualification_sha = qualification_core.pop(
            "qualification_sha256", None
        )
        if observed_qualification_sha != _canonical_sha256(qualification_core):
            raise StageAInputError("component dependency qualification is stale")
        activation = _object(
            qualification.get("activation"), "component dependency activation"
        )
        domain = _object(
            activation.get("domain"), "component dependency activation domain"
        )
        if (
            qualification.get("status") != "qualified"
            or activation.get("authorized") is not True
            or domain.get("kind") != "total"
        ):
            raise StageAInputError(
                f"component dependency is not totally qualified: {target_component_id}"
            )
        if (
            qualification.get("component_id") != target_component_id
            or qualification.get("bindings", {}).get("component_workspace_sha256")
            != workspace["workspace_sha256"]
            or qualification.get("bindings", {}).get("refinement_sha256")
            != refinement["refinement_sha256"]
        ):
            raise StageAInputError(
                f"component dependency qualification binding is stale: {target_component_id}"
            )
        child = _object(refinement.get("component"), "dependency component binding")
        child_units = set(
            _string_array(child.get("unit_ids"), "dependency component unit IDs")
        )
        if (
            child.get("id") != target_component_id
            or child.get("entry_rva") != target_rva
            or target_unit_id not in child_units
        ):
            raise StageAInputError(
                f"selected call target does not match qualified component {target_component_id}"
            )
        portable_source = root / str(workspace["files"]["portable_source"])
        portable_header = root / str(workspace["files"]["portable_header"])
        if (
            not portable_source.is_file()
            or not portable_header.is_file()
            or sha256_file(portable_source)
            != refinement.get("bindings", {}).get("portable_source_sha256")
            or sha256_file(portable_header)
            != refinement.get("bindings", {}).get("portable_header_sha256")
        ):
            raise StageAInputError(
                f"component dependency source binding is stale: {target_component_id}"
            )
        dependency = _CheckedComponentDependency(
            root=root,
            declaration=declaration,
            workspace=workspace,
            refinement=refinement,
            qualification=qualification,
        )
        dependency.proof_binding()
        checked.append(dependency)
    return checked


def _materialize_component_dependency_evidence(
    *,
    root: Path,
    dependencies: Sequence[_CheckedComponentDependency],
    materialize: bool,
) -> list[dict[str, Any]]:
    bindings: list[dict[str, Any]] = []
    for dependency in dependencies:
        component_id = str(dependency.declaration["target_component_id"])
        evidence_root = Path("contract") / "component-dependencies" / _slug(
            component_id
        )
        destination = root / evidence_root
        if materialize:
            destination.mkdir(parents=True, exist_ok=True)
        sources = {
            "workspace": dependency.root / "component-workspace.json",
            "refinement": dependency.root
            / str(dependency.workspace["files"]["refinement"]),
            "qualification": dependency.root / "component-qualification.json",
        }
        evidence: dict[str, Any] = {}
        for kind, source in sources.items():
            if not source.is_file():
                raise StageAInputError(
                    f"qualified component dependency omits {kind}: {component_id}"
                )
            target = destination / f"{kind}.json"
            if materialize:
                shutil.copyfile(source, target)
            evidence[kind] = {
                "path": target.relative_to(root).as_posix(),
                "sha256": sha256_file(source),
            }
        source_root = Path("src") / "component-dependencies" / _slug(component_id)
        source_destination = root / source_root
        if materialize:
            source_destination.mkdir(parents=True, exist_ok=True)
        portable_sources = {
            "portable_source": dependency.root
            / str(dependency.workspace["files"]["portable_source"]),
            "portable_header": dependency.root
            / str(dependency.workspace["files"]["portable_header"]),
        }
        for kind, source in portable_sources.items():
            suffix = ".c" if kind == "portable_source" else ".h"
            target = source_destination / f"implementation{suffix}"
            if materialize:
                shutil.copyfile(source, target)
            evidence[kind] = {
                "path": target.relative_to(root).as_posix(),
                "sha256": sha256_file(source),
            }
        core = dependency.proof_binding()
        core.pop("binding_sha256", None)
        core["evidence"] = evidence
        bindings.append({**core, "binding_sha256": _canonical_sha256(core)})
    return bindings


def _attach_component_dependency_support_sources(
    *,
    root: Path,
    backend_workspace: Mapping[str, Any],
    dependency_bindings: Sequence[Mapping[str, Any]],
) -> None:
    if not dependency_bindings:
        return
    files = _object(backend_workspace.get("files"), "backend workspace files")
    manifest_path = root / str(files["replacement_manifest"])
    payload = _read_object(manifest_path, "region replacement manifest")
    support = _array(payload.get("support_sources", []), "replacement support sources")
    known_paths = {str(item.get("path")) for item in support if isinstance(item, Mapping)}
    for raw_binding in dependency_bindings:
        binding = _object(raw_binding, "component dependency binding")
        evidence = _object(binding.get("evidence"), "component dependency evidence")
        for kind, role in (
            ("portable_source", "adapter_support"),
            ("portable_header", "portable_header"),
        ):
            artifact = _object(evidence.get(kind), f"component dependency {kind}")
            path = str(artifact["path"])
            if path in known_paths:
                raise StageAInputError(
                    f"component dependency support path is duplicated: {path}"
                )
            support.append(
                {
                    "path": path,
                    "sha256": str(artifact["sha256"]),
                    "role": role,
                }
            )
            known_paths.add(path)
    payload["support_sources"] = support
    write_json(manifest_path, payload)


def _normalized_component_call_plan(
    *,
    component: Mapping[str, Any],
    component_dependencies: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    boundary = _object(component.get("machine_boundary"), "component machine boundary")
    effects = _object(boundary.get("effects", {}), "component machine effects")
    if not component_dependencies:
        events = _array(
            effects.get("external_events", []), "component external events"
        )
        return {
            "status": "not_applicable",
            "calls": [],
            "remaining_events": copy.deepcopy(events),
            "remaining_exits": copy.deepcopy(boundary.get("exits", [])),
            "external_trace": [
                _normalized_external_trace_event(item) for item in events
            ],
        }
    calls = []
    selected_keys: set[tuple[str, int]] = set()
    for dependency in component_dependencies:
        binding = _object(dependency, "checked component dependency")
        declared = next(
            (
                _object(item, "selected component call")
                for item in _array(component.get("component_calls"), "component calls")
                if item.get("target_component_id") == binding.get("target_component_id")
                and item.get("target_rva") == binding.get("target_rva")
            ),
            None,
        )
        if declared is None:
            raise StageAInputError(
                "checked component dependency is absent from selected calls"
            )
        callsites = copy.deepcopy(
            _array(declared.get("callsites"), "selected component callsites")
        )
        for callsite in callsites:
            selected_keys.add(
                (str(callsite["source_unit_id"]), int(binding["target_rva"]))
            )
        calls.append({**copy.deepcopy(dict(binding)), "callsites": callsites})

    def selected_event(item: Any) -> bool:
        row = _object(item, "component effect event")
        event = _object(row.get("event", row), "component call event")
        return event.get("kind") == "internal_call" and (
            str(row.get("unit_id")), int(event.get("target_rva", -1))
        ) in selected_keys

    def selected_exit(item: Any) -> bool:
        row = _object(item, "component machine exit")
        return row.get("kind") == "internal_call" and (
            str(row.get("source_unit_id")), int(row.get("target_rva", -1))
        ) in selected_keys

    events = _array(effects.get("external_events", []), "component external events")
    exits = _array(boundary.get("exits", []), "component machine exits")
    matched_events = [item for item in events if selected_event(item)]
    matched_exits = [item for item in exits if selected_exit(item)]
    if len(matched_events) != len(selected_keys) or len(matched_exits) != len(
        selected_keys
    ):
        raise StageAInputError(
            "selected component dependencies do not exactly cover call effects and exits"
        )
    dependency_by_key = {
        (str(callsite["source_unit_id"]), int(binding["target_rva"])): binding
        for binding in component_dependencies
        for callsite in _array(binding.get("callsites", []), "component dependency callsites")
    }
    external_trace = []
    for item in events:
        row = _object(item, "component effect event")
        event = _object(row.get("event", row), "component call event")
        key = (str(row.get("unit_id")), int(event.get("target_rva", -1)))
        if event.get("kind") == "internal_call" and key in dependency_by_key:
            external_trace.extend(
                copy.deepcopy(
                    _array(
                        dependency_by_key[key].get("external_trace", []),
                        "component dependency external trace",
                    )
                )
            )
        else:
            external_trace.append(_normalized_external_trace_event(row))
    return {
        "status": "checked",
        "calls": calls,
        "remaining_events": copy.deepcopy(
            [item for item in events if not selected_event(item)]
        ),
        "remaining_exits": copy.deepcopy(
            [item for item in exits if not selected_exit(item)]
        ),
        "external_trace": external_trace,
    }


def _normalized_external_trace_event(value: Any) -> dict[str, Any]:
    row = _object(value, "component external event binding")
    event = _object(row.get("event", row), "component external event")
    kind = event.get("kind")
    if kind == "indirect_call":
        if (
            not isinstance(row.get("unit_id"), str)
            or not row.get("unit_id")
            or event.get("effect_model")
            != "uninterpreted_indirect_call_response_v1"
            or not isinstance(event.get("return_rva"), int)
            or not isinstance(event.get("register_inputs"), Mapping)
            or not isinstance(event.get("stack_inputs"), list)
        ):
            raise StageAInputError(
                "component indirect call has no exact machine-boundary descriptor"
            )
        return {"kind": "indirect_call", "identity": "indirect-call"}
    if kind != "external_call":
        raise StageAInputError(
            "component has an uncontracted event in its external trace"
        )
    dll = event.get("dll")
    symbol = event.get("symbol")
    if not isinstance(dll, str) or not dll or not isinstance(symbol, str) or not symbol:
        raise StageAInputError("component external event has no exact import identity")
    return {"kind": "external_call", "identity": f"{dll}!{symbol}"}


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


def _load_bound_interface_refinement(
    root: Path,
    metadata: Mapping[str, Any],
    refinement: Mapping[str, Any],
) -> dict[str, Any]:
    relative_path = metadata.get("files", {}).get(
        "logical_interface_refinement"
    )
    if not isinstance(relative_path, str) or not relative_path:
        raise StageAInputError(
            "component workspace omits checked logical interface refinement"
        )
    path = root / relative_path
    payload = _read_object(path, "component interface refinement")
    _require_format(
        payload,
        COMPONENT_INTERFACE_REFINEMENT_FORMAT,
        "component interface refinement",
    )
    expected = payload.get("refinement_sha256")
    core = copy.deepcopy(payload)
    core.pop("refinement_sha256", None)
    if expected != _canonical_sha256(core):
        raise StageAInputError("component interface refinement self-hash is stale")
    if (
        expected
        != metadata.get("bindings", {}).get(
            "logical_interface_refinement_sha256"
        )
        or expected
        != refinement.get("bindings", {}).get(
            "logical_interface_refinement_sha256"
        )
        or expected
        != refinement.get("logical_interface_refinement", {}).get(
            "refinement_sha256"
        )
        or sha256_file(path)
        != refinement.get("bindings", {}).get(
            "logical_interface_artifact_sha256"
        )
    ):
        raise StageAInputError(
            "component workspace/interface refinement binding is stale"
        )
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


def _array(value: Any, description: str) -> list[Any]:
    if not isinstance(value, list):
        raise StageAInputError(f"{description} must be an array")
    return value


def _string_array(value: Any, description: str) -> list[str]:
    rows = _array(value, description)
    if any(not isinstance(item, str) or not item for item in rows):
        raise StageAInputError(f"{description} must contain non-empty strings")
    return list(rows)


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

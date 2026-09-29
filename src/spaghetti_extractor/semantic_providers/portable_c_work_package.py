"""Direct V6 work-package to portable semantic-provider qualification.

This is the clean component path.  V4 contracts, V5 machine-binding receipts,
component-implementation reducers, and aggregate activation graphs are not
inputs.  The existing proof kernel and overlay renderer are reused through an
in-memory normalized view; no compatibility artifact is emitted.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import tempfile
from typing import Mapping, Sequence

from .allocation_inputs import allocation_producer_inputs
from ..artifacts.artifact_set import canonical_sha256_v3
from ..components.component_exact_c_slice import write_component_exact_c_slice_v1
from ..components.bisimulation import (
    ComponentBisimulationError,
    ComponentBisimulationIntentV1,
    build_component_proof_plan_v1,
    load_component_bisimulation_intent,
)
from ..components.bisimulation_refinement import (
    build_typed_proof_service_thunk_renderer,
    check_bisimulation_refinement,
)
from .portable_c_source_contracts import check_provider_source_contracts
from .portable_c_relations import _checked_relation_boundary_operations
from .portable_c_shared_contracts import prepare_provider_shared_contract, check_provider_shared_binding
from ..components.bisimulation_shared_model import SHARED_CONTRACT_POLICY
from ..components.bisimulation_local_views import has_local_views
from .portable_c_postconditions import (
    normal_exit_intent, checked_provider_postconditions, validate_provider_postconditions,
    validate_provider_postcondition_request,
)
from ..components.bisimulation_readable_entry import checked_memory_summary_facts
from ..components.component_c_v5 import render_component_c_headers_v5
from ..components.machine_overlay_v5 import render_component_machine_overlay_v5, render_bound_proof_overlay
from ..components.portable_object import compile_portable_component_objects
from ..components.refinement_v5 import (
    _compile_kernel_semantic_contract,
)
from ..components.contextual_bisimulation import (
    build_contextual_refinement_v2,
    operation_sources_from_package,
    validate_contextual_refinement_v2,
)
from ..components.semantic_contract import load_transfer_v2_refinement_universe
from ..components.source import (
    component_operation_symbols,
    load_component_source_package,
)
from ..components.source_profile import check_component_source_profile
from ..semantic_link.module_v2 import LinkedSemanticModuleV2
from ..semantic_objects.object_authority import MachineObjectAuthorityV2
from ..pe32.module_interface import Pe32ModuleInterfaceV2
from ..transfer.plan import load_executable_transfer_plan
from ..transfer.runtime_abi import exact_runtime_header
from .exact_context import build_exact_context
from ..util import sha256_file, write_json
from .encapsulated_owned import check_encapsulated_owned_admission
from .portable_c_common import (
    PortableCWorkPackageError,
    fail as _fail,
    load_json as _load_json,
)
from .portable_c_inputs import (
    _checked_callback_projection_capabilities_v2,
    _component_proof_world_v1,
    _direct_component_view,
    _direct_operation_rows,
    _validate_exact_c_slice,
)
from .qualification_v2 import (
    SemanticProviderQualificationV2,
    SemanticProviderQualificationV2Error,
    write_semantic_provider_qualification_v2,
)
from .slices_v2 import SemanticSliceV2


def _has_callback_projection(
    operations: Sequence[Mapping[str, object]],
) -> bool:
    """Return whether the operation view imports a callable capability."""

    def contains(value: object) -> bool:
        if isinstance(value, Mapping):
            return value.get("kind") == "callback_handle" or any(
                contains(item) for item in value.values()
            )
        if isinstance(value, (list, tuple)):
            return any(contains(item) for item in value)
        return False

    return any(contains(row["machine_projection"]) for row in operations)


def _component_operation_provider_ids(
    operations: Sequence[Mapping[str, object]],
) -> set[str]:
    result: set[str] = set()
    for operation in operations:
        projection = operation.get("machine_projection")
        if not isinstance(projection, Mapping):
            _fail("V6 operation machine projection is malformed")
        bindings = projection.get("service_bindings", [])
        if not isinstance(bindings, list):
            _fail("V6 service binding inventory is malformed")
        for raw_binding in bindings:
            if not isinstance(raw_binding, Mapping):
                _fail("V6 service binding is malformed")
            provider = raw_binding.get("provider")
            if not isinstance(provider, Mapping):
                _fail("V6 service provider is malformed")
            if provider.get("kind") != "component_operation":
                continue
            component_id = provider.get("component_id")
            if not isinstance(component_id, str) or not component_id:
                _fail("V6 component-operation provider identity is malformed")
            result.add(component_id)
    return result


def write_portable_c_work_package_provider_v2(
    *,
    semantic_slice: Path,
    binding_intent: Path,
    interface_package: Path,
    source_package: Path,
    transfer_plan: Path,
    resolved_external_environment: Path,
    machine_object_authority: Path,
    host_compiler: Path,
    pe32_compiler: Path,
    nm: Path,
    cbmc: Path,
    provider_id: str,
    proof_classification: str,
    out: Path,
    linked_semantic_module: Path | None = None,
    generated_choices: Path | None = None,
    provider_entry_units: Mapping[str, str] | None = None,
    relation_intent: Path | None = None,
    bisimulation_intent: Path | None = None,
    exact_c_slice: Path | None = None,
    provider_components: Mapping[str, Mapping[str, Path]] | None = None,
    provenance_artifacts: Mapping[str, Path] | None = None,
    interaction_contract_catalog: Path | None = None,
    timeout_seconds: int = 300,
    source_entry_timeout_seconds: int | None = None,
    source_summary_workspace: Path | None = None,
    proof_workspace: Path | None = None, previous_query_evidence: Path | None = None,
    shared_source_contract_artifacts: Path | None = None,
    smt_solver: Path | None = None,
    runtime_assurance: Mapping[str, object] | None = None,
    selected_obligations: list[dict[str, str]] | None = None,
) -> dict[str, Path]:
    """Prove, compile, and qualify one direct V6 portable component."""
    from ..components.bisimulation_assurance import checked_implemented_runtime_assurance
    runtime_assurance = checked_implemented_runtime_assurance(runtime_assurance)
    if source_entry_timeout_seconds is not None and (
            type(source_entry_timeout_seconds) is not int or source_entry_timeout_seconds <= 0
            or runtime_assurance is None):
        _fail('entry query timeout requires a positive integer and explicit conditional assurance')
    from ..components.conditional_check_result import checked_obligation_selection
    selected_obligations = checked_obligation_selection(selected_obligations)
    output = Path(out)
    if (runtime_assurance is not None or selected_obligations is not None) and any((output / name).exists() for name in (
            "semantic-provider-qualification.json", "provider-object-manifest.json",
            "definition-choices.json", "implementation-choices.json")):
        _fail("conditional check output contains activation artifacts")
    output.mkdir(parents=True, exist_ok=True)
    if proof_classification not in {"machine_overlay", "encapsulated_owned"}:
        _fail("direct portable provider proof classification is unsupported")
    semantic_slice_model = SemanticSliceV2.parse(
        _load_json(
            Path(semantic_slice),
            "component semantic slice V2",
        )
    )

    transfer_path = Path(transfer_plan)
    transfer_payload, transfers = load_executable_transfer_plan(
        transfer_path,
        require_complete=False,
    )
    authority = MachineObjectAuthorityV2.parse(
        _load_json(
            Path(machine_object_authority),
            "machine object authority V2",
        )
    )
    module_interface_path = (
        Path(machine_object_authority).parent / "module-interface.json"
    )
    module_interface = Pe32ModuleInterfaceV2.load(
        module_interface_path,
        require_complete=True,
    ).payload
    transfer_bindings = transfer_payload["bindings"]
    if (
        authority.bindings.get("original_pe_sha256") != transfer_bindings["pe_sha256"]
        or authority.bindings.get("module_interface_sha256")
        != sha256_file(module_interface_path)
        or module_interface["identity"]["pe_sha256"] != transfer_bindings["pe_sha256"]
    ):
        _fail("component proof image/object bindings name another module")
    producer_inputs = None
    if any(rule.locator.kind == "external_allocation" for rule in authority.rules):
        producer_inputs = allocation_producer_inputs(authority=authority, transfers=transfers,
            resolved_environment=_load_json(Path(resolved_external_environment), "resolved external environment"),
            transfer_plan=transfer_payload, module_interface=module_interface)
        write_json(output / "allocation-producer-inputs.json", producer_inputs)
    allocation_requirements = (None if producer_inputs is None else sorted(
        [row['class_requirement'] for row in producer_inputs['classes']], key=lambda row: row['authority']['id']))
    loader = module_interface["loader"]
    machine_image = {
        "image_size": loader["image_size"],
        "module_interface_sha256": module_interface["interface_sha256"],
        "pe_sha256": transfer_bindings["pe_sha256"],
        "preferred_base": loader["preferred_base"],
    }
    bundle, contract, binding, binding_model = _direct_component_view(
        binding_intent=Path(binding_intent),
        interface_package=Path(interface_package),
        transfer_payload=transfer_payload,
        semantic_slice_sha256=semantic_slice_model.identity,
    )
    from .portable_c_inputs import pending_local_check_requirements
    pending_requirements = pending_local_check_requirements(bundle=bundle, contract=contract,
        binding=binding, binding_model=binding_model, runtime_assurance=runtime_assurance)
    operations = _direct_operation_rows(
        binding=binding_model,
        semantic_slice=semantic_slice_model,
    )
    component_id = bundle.interface.identity
    provenance_sha256s: dict[str, str] = {}
    for artifact_id, artifact_path in sorted((provenance_artifacts or {}).items()):
        if (
            not artifact_id
            or artifact_id[0].isalnum() is False
            or any(
                not (character.isalnum() or character in "._-")
                for character in artifact_id
            )
        ):
            _fail("portable provider provenance identity is malformed")
        path = Path(artifact_path)
        if not path.is_file():
            _fail("portable provider provenance artifact is not a file")
        provenance_sha256s[artifact_id] = sha256_file(path)
    qualification_input = {
        **({'selected_obligations': selected_obligations} if selected_obligations is not None else {}),
        **({"boundary_requirements": pending_requirements} if pending_requirements else {}),
        **({"runtime_assurance": runtime_assurance} if runtime_assurance is not None else {}),
        "component_id": component_id,
        "proof_classification": proof_classification,
        "semantic_slice_sha256": semantic_slice_model.identity,
        "binding_intent_sha256": binding_model.intent_sha256,
        "interface_sha256": bundle.interface.interface_sha256,
        "schema_sha256": bundle.interface.schema_sha256,
        "executable_transfer_plan_sha256": sha256_file(transfer_path),
        "module_interface_sha256": module_interface["interface_sha256"],
        "provenance_artifact_sha256s": provenance_sha256s,
        "bisimulation_intent_sha256": (
            None
            if bisimulation_intent is None
            else sha256_file(Path(bisimulation_intent))
        ),
        "exact_c_slice_manifest_sha256": (
            None if exact_c_slice is None else sha256_file(Path(exact_c_slice))
        ),
    }
    requested_postconditions = (None if relation_intent is None else normal_exit_intent(
        _load_json(Path(relation_intent), "component relation intent"), bundle=bundle))
    if requested_postconditions is not None:
        qualification_input["normal_exit_relation_intent_sha256"] = requested_postconditions.intent_sha256
    if shared_source_contract_artifacts is not None:
        qualification_input["shared_source_contract_file_sha256"] = sha256_file(
            Path(shared_source_contract_artifacts) / "local-contract-result.json")
    if producer_inputs is not None:
        qualification_input["allocation_producer_inputs_sha256"] = producer_inputs["producer_inputs_sha256"]
    has_callback_projection = _has_callback_projection(operations)
    needs_linked_module = (
        proof_classification == "encapsulated_owned" or has_callback_projection
        or any(row["machine_projection"].get("operation", {}).get("continuation_unit_ids") for row in operations)
    )
    if needs_linked_module and linked_semantic_module is None:
        _fail("direct portable provider requires linked callback/ownership/context facts")
    linked = (
        None
        if linked_semantic_module is None
        else LinkedSemanticModuleV2.load(
            Path(linked_semantic_module),
            require_complete=False,
        )
    )
    if (
        linked is not None
        and linked.payload["bindings"]["executable_transfer_plan_sha256"]
        != transfer_payload["plan_sha256"]
    ):
        _fail("direct portable provider linked transfer binding is stale")
    qualification_input["linked_semantic_module_sha256"] = (
        None if linked is None else linked.identity
    )

    source_root = Path(source_package)
    source = load_component_source_package(source_root)
    if source.get("lift_unit_id") != component_id:
        _fail("component source package binds another V6 component")
    if runtime_assurance is not None:
        qualification_input["implementation_sha256"] = source["implementation_sha256"]
    symbols = component_operation_symbols(source)
    if set(symbols) != {str(row["operation_id"]) for row in operations}:
        _fail("component source symbols disagree with the V6 binding")

    provider_entries = dict(provider_entry_units or {})
    direct_provider_ids = _component_operation_provider_ids(operations)
    provider_paths = dict(provider_components or {})
    if component_id in provider_paths:
        _fail("V6 connected-provider closure repeats the root component")
    provider_proof_inputs: dict[str, dict[str, object]] = {}
    provider_edges: dict[str, set[str]] = {}
    provider_transfer_ids: set[str] = set()
    provider_view_bindings: dict[str, Mapping[str, str]] = {}
    exact_dependency_components: dict[str, Mapping[str, object]] = {}
    for referenced_component_id in sorted(provider_paths):
        paths = provider_paths[referenced_component_id]
        provider_slice = SemanticSliceV2.parse(
            _load_json(
                Path(paths["semantic_slice"]),
                f"V6 provider {referenced_component_id} semantic slice",
            )
        )
        (
            provider_bundle,
            provider_contract,
            provider_binding,
            provider_binding_model,
        ) = _direct_component_view(
            binding_intent=Path(paths["binding_intent"]),
            interface_package=Path(paths["interface_package"]),
            transfer_payload=transfer_payload,
            semantic_slice_sha256=provider_slice.identity,
        )
        if (
            provider_bundle.interface.identity != referenced_component_id
            or provider_contract.status != "checked"
            or provider_binding.status != "checked"
        ):
            _fail("V6 component-operation provider view is incomplete")
        provider_operations = _direct_operation_rows(
            binding=provider_binding_model,
            semantic_slice=provider_slice,
        )
        provider_edges[referenced_component_id] = _component_operation_provider_ids(
            provider_operations
        )
        provider_source_root = Path(paths["source_package"])
        provider_source = load_component_source_package(provider_source_root)
        provider_symbols = component_operation_symbols(provider_source)
        if provider_source.get("lift_unit_id") != referenced_component_id or set(
            provider_symbols
        ) != {str(row["operation_id"]) for row in provider_operations}:
            _fail("V6 connected-provider source package is stale")
        provider_profile = check_component_source_profile(package=provider_source_root)
        if "conditional_refinement" in paths:
            from .portable_c_conditional_supplier import load_conditional_supplier
            provider_proof_inputs[referenced_component_id] = load_conditional_supplier(
                paths=paths, component_id=referenced_component_id, parent_assurance=runtime_assurance,
                bundle=provider_bundle, contract=provider_contract, binding=provider_binding,
                binding_model=provider_binding_model, operations=provider_operations,
                source_root=provider_source_root, source=provider_source, symbols=provider_symbols,
                profile=provider_profile, slice_id=provider_slice.identity,
                transfer_plan_sha256=sha256_file(transfer_path))
        else:
            try:
                provider_qualification = SemanticProviderQualificationV2.load(
                    Path(paths["qualification"])
                )
            except (
                OSError,
                UnicodeError,
                json.JSONDecodeError,
                SemanticProviderQualificationV2Error,
            ) as exc:
                _fail(f"V6 connected-provider qualification is invalid: {exc}")
            provider_contextual = _load_json(
                Path(paths["contextual_refinement"]),
                f"V6 provider {referenced_component_id} contextual refinement",
            )
            provider_proof = provider_contextual.get("proof")
            if not isinstance(provider_proof, Mapping):
                _fail("V6 connected-provider contextual proof is missing")
            provider_proof_core = dict(provider_proof)
            provider_proof_sha256 = provider_proof_core.pop("receipt_sha256", None)
            provider_facets = {
                str(row.get("name")): str(row.get("status"))
                for row in provider_qualification.payload.get("facets", [])
                if isinstance(row, Mapping)
            }
            provider_proof_bindings = provider_proof.get("bindings")
            provider_root = Path(paths["contextual_refinement"]).parent
            provider_proof_plan = _load_json(
                provider_root / "component-proof-plan-v1.json",
                f"V6 provider {referenced_component_id} proof plan",
            )
            provider_exact_slice = _load_json(
                provider_root / "exact-c" / "component-exact-c-slice-v1.json",
                f"V6 provider {referenced_component_id} exact-C slice",
            )
            provider_contextual_input = provider_contextual.get("qualification_input")
            provider_contextual_input_sha256 = provider_contextual.get(
                "qualification_input_sha256"
            )
            provider_plan_bindings = provider_proof_plan.get("bindings")
            provider_checker = provider_proof.get("checker")
            provider_models = provider_proof.get("models")
            provider_dependencies = set(provider_qualification.payload["dependencies"])
            provider_refinement_receipt = provider_contextual.get("receipt_sha256")
            if (
                not isinstance(provider_contextual_input, Mapping)
                or provider_contextual_input_sha256
                != canonical_sha256_v3(provider_contextual_input)
                or not isinstance(provider_plan_bindings, Mapping)
                or not isinstance(provider_checker, Mapping)
                or not isinstance(provider_models, Mapping)
                or provider_contextual.get("proof_plan") != provider_proof_plan
                or provider_contextual.get("exact_c_slice") != provider_exact_slice
                or provider_contextual.get("source_package_sha256")
                != provider_source.get("implementation_sha256")
                or provider_contextual_input.get("component_id") != referenced_component_id
                or provider_contextual_input.get("semantic_slice_sha256")
                != provider_slice.identity
                or provider_contextual_input.get("binding_intent_sha256")
                != provider_binding_model.intent_sha256
                or provider_contextual_input.get("interface_sha256")
                != provider_bundle.interface.interface_sha256
                or provider_contextual_input.get("executable_transfer_plan_sha256")
                != sha256_file(transfer_path)
                or f"contextual-refinement:{provider_refinement_receipt}"
                not in provider_dependencies
                or f"component-proof-plan:{provider_proof_plan.get('plan_sha256')}"
                not in provider_dependencies
                or "component-exact-c-slice:"
                + str(provider_exact_slice.get("slice_sha256"))
                not in provider_dependencies
                or provider_refinement_receipt
                != canonical_sha256_v3(
                    {
                        "qualification_input_sha256": provider_contextual_input_sha256,
                        "source_package_sha256": provider_source["implementation_sha256"],
                        "semantic_contract_sha256": provider_plan_bindings.get(
                            "semantic_contract_sha256"
                        ),
                        "cbmc_sha256": provider_checker.get("cbmc_sha256"),
                        "proof": provider_proof,
                        "relation_evidence": provider_contextual.get("relation_evidence"),
                        **({"normal_exit_postconditions": provider_contextual["normal_exit_postconditions"]}
                           if "normal_exit_postconditions" in provider_contextual else {}),
                        "proof_plan_sha256": provider_proof_plan.get("plan_sha256"),
                        "exact_c_slice_sha256": provider_exact_slice.get("slice_sha256"),
                    }
                )
            ):
                _fail("V6 connected-provider wrapper or dependency binding is stale")
            try:
                validate_contextual_refinement_v2(
                    provider_proof,
                    proof_plan=provider_proof_plan,
                    exact_c_slice=provider_exact_slice,
                    implementation_sha256=str(provider_source["implementation_sha256"]),
                )
            except ComponentBisimulationError as exc:
                _fail(f"V6 connected-provider contextual proof is invalid: {exc}")
            try:
                validate_provider_postcondition_request(provider_contextual.get("normal_exit_postconditions"),
                    requested_sha256=provider_contextual_input.get("normal_exit_relation_intent_sha256"))
            except ValueError as error:
                _fail(str(error))
            shared_source_requested = provider_contextual_input.get("shared_source_contract_file_sha256")
            shared_source_bound = provider_models.get("source_summary_contracts", {}).get("certificate", {}).get("policy") == SHARED_CONTRACT_POLICY
            if (shared_source_requested is not None) != shared_source_bound:
                _fail("V6 shared source contract and qualification request disagree")
            if (
                provider_qualification.payload.get("status") != "complete"
                or provider_qualification.provider_kind != "qualified_portable_c"
                or provider_qualification.semantic_slice.identity != provider_slice.identity
                or provider_contextual.get("status") != "satisfied"
                or provider_proof.get("status") != "satisfied"
                or provider_proof.get("activation_authorized") is not True
                or provider_proof_sha256 != canonical_sha256_v3(provider_proof_core)
                or not isinstance(provider_proof_bindings, Mapping)
                or provider_proof_bindings.get("implementation_sha256")
                != provider_source.get("implementation_sha256")
                or provider_facets.get("bisimulation") != "checked"
                or provider_facets.get("contextual_refinement") != "checked"
            ):
                _fail("V6 connected-provider proof summary is incomplete or stale")
            provider_classification = str(
                paths.get("proof_classification", "machine_overlay")
            )
            if provider_classification not in {
                "machine_overlay",
                "encapsulated_owned",
            }:
                _fail("V6 connected-provider proof classification is unsupported")
            provider_proof_inputs[referenced_component_id] = {
                "bundle": provider_bundle,
                "contract": provider_contract,
                "binding": provider_binding,
                "binding_model": provider_binding_model,
                "operations": provider_operations,
                "source_root": provider_source_root,
                "source": provider_source,
                "symbols": provider_symbols,
                "source_profile": provider_profile,
                "qualification_sha256": provider_qualification.identity,
                "contextual_refinement_sha256": str(
                    provider_contextual.get("receipt_sha256", "")
                ),
                "proof_receipt_sha256": str(provider_proof_sha256),
                "proof_classification": provider_classification,
                "proof_machine_overlay_sha256": provider_models["machine_overlay_sha256"],
                "proof_overlay_sha256": provider_models["proof_overlay_sha256"],
                "trusted_adapter_lowering": provider_models.get("trusted_adapter_lowering"),
                "relation_evidence": provider_contextual.get("relation_evidence", []),
                "normal_exit_postconditions": provider_contextual.get("normal_exit_postconditions"),
                "shared_source_contract_file_sha256": shared_source_requested,
                "source_summary_contracts": provider_models.get("source_summary_contracts"),
                "proof_system": {key: provider_contextual[key] for key in ("proof", "proof_plan", "exact_c_slice")},
                "binding_intent": provider_binding_model.to_payload(),
                "proof_artifacts": Path(paths["contextual_refinement"]).parent / "proof-diagnostics",
                "source_summary_artifacts": Path(paths["contextual_refinement"]).parent / "source-summary-contracts",
                **checked_memory_summary_facts(provider_proof,
                    artifacts=Path(paths["contextual_refinement"]).parent / "proof-diagnostics"),
            }
        provider_transfer_ids.update(
            unit_id
            for operation in provider_binding_model.operations
            for unit_id in operation.semantics.transfer_ids
        )
        provider_view_bindings[referenced_component_id] = {
            "semantic_slice_sha256": provider_slice.identity,
            "binding_intent_sha256": provider_binding_model.intent_sha256,
            "interface_sha256": provider_bundle.interface.interface_sha256,
            "source_implementation_sha256": str(
                provider_source["implementation_sha256"]
            ),
            "source_profile_sha256": str(provider_profile["receipt_sha256"]),
            "qualification_sha256": provider_proof_inputs[referenced_component_id]["qualification_sha256"],
            "contextual_refinement_sha256": provider_proof_inputs[referenced_component_id]["contextual_refinement_sha256"],
            "proof_receipt_sha256": provider_proof_inputs[referenced_component_id]["proof_receipt_sha256"],
            "proof_classification": provider_proof_inputs[referenced_component_id]["proof_classification"],
            **({"assurance": provider_proof_inputs[referenced_component_id]["assurance"]}
               if "assurance" in provider_proof_inputs[referenced_component_id] else {}),
        }
        exact_dependency_components[referenced_component_id] = {
            "binding_intent_sha256": provider_binding_model.intent_sha256,
            "unit_ids": sorted(
                {
                    unit_id
                    for operation in provider_binding_model.operations
                    for unit_id in operation.semantics.transfer_ids
                }
            ),
            "entry_rvas": sorted(
                {
                    rva
                    for operation in provider_binding_model.operations
                    for rva in operation.semantics.entry_rvas
                }
            ),
            "operations": [
                {
                    "unit_ids": list(operation.semantics.transfer_ids),
                    "entry_rvas": list(operation.semantics.entry_rvas),
                }
                for operation in provider_binding_model.operations
            ],
        }
    reachable_provider_ids: set[str] = set()
    frontier = set(direct_provider_ids)
    while frontier:
        candidate = frontier.pop()
        if candidate == component_id or candidate in reachable_provider_ids:
            continue
        reachable_provider_ids.add(candidate)
        frontier.update(provider_edges.get(candidate, set()))
    missing_provider_views = sorted(reachable_provider_ids - set(provider_paths))
    if missing_provider_views:
        _fail(
            "V6 connected-provider closure is missing components: "
            + repr(missing_provider_views)
        )
    unused_provider_views = sorted(set(provider_paths) - reachable_provider_ids)
    if unused_provider_views:
        _fail(
            "V6 connected-provider closure has unreachable components: "
            + repr(unused_provider_views)
        )
    missing_provider_ids = sorted(
        (reachable_provider_ids | direct_provider_ids) - set(provider_entries)
    )
    if missing_provider_ids:
        _fail(
            "V6 component-operation provider entries are missing: "
            + repr(missing_provider_ids)
        )
    if linked is None and any(
        str(provider_proof_inputs[item]["proof_classification"]) == "encapsulated_owned"
        or _has_callback_projection(
            provider_proof_inputs[item]["operations"]  # type: ignore[arg-type]
        )
        for item in reachable_provider_ids
    ):
        _fail("V6 connected-provider closure requires linked callback/ownership facts")
    qualification_input["provider_components"] = provider_view_bindings
    qualification_input_sha256 = canonical_sha256_v3(qualification_input)
    required_transfer_ids = sorted(
        {str(unit_id) for row in operations for unit_id in row["context_transfer_ids"]}
        | provider_transfer_ids
        | {provider_entries[item] for item in reachable_provider_ids}
    )
    transfer_universe = load_transfer_v2_refinement_universe(
        transfer_plan=transfer_path,
        required_unit_ids=required_transfer_ids,
    )
    portable_payload, portable, semantic_contract, service_rows = (
        _compile_kernel_semantic_contract(
            bundle=bundle,
            contract=contract,
            machine_binding=binding,
            transfer_universe=transfer_universe,
            finite_control_routes=transfer_payload["finite_control_routes"],
            resolved_external_environment=Path(resolved_external_environment),
            provider_entry_units={
                provider_component_id: provider_entries[provider_component_id]
                for provider_component_id in sorted(direct_provider_ids)
            },
            machine_image=machine_image,
        )
    )
    _boundary_operations, relation_evidence = _checked_relation_boundary_operations(
        component_id=component_id,
        bundle=bundle,
        portable=portable,
        semantic_contract=semantic_contract,
        relation_intent=relation_intent,
        interaction_contract_catalog=interaction_contract_catalog,
    )
    source_profile = check_component_source_profile(package=source_root)
    resolved = _load_json(
        Path(resolved_external_environment),
        "resolved external environment",
    )
    callback_capabilities: dict[str, Mapping[str, object]] = {}
    if has_callback_projection:
        assert linked is not None and linked_semantic_module is not None
        module_interface = _load_json(
            Path(linked_semantic_module).parent / "module-interface.json",
            "linked module interface",
        )
        callback_capabilities = _checked_callback_projection_capabilities_v2(
            operations=operations,
            linked=linked,
            module_interface=module_interface,
        )
    authored_bisimulation = (
        ComponentBisimulationIntentV1.create(
            component_id=component_id,
            operations=[{"operation_id": operation_id, "syncs": []}
                        for operation_id in sorted(symbols)],
        ) if bisimulation_intent is None
        else load_component_bisimulation_intent(Path(bisimulation_intent))
    )
    overlay = render_component_machine_overlay_v5(
        bundle=bundle,
        contract=contract,
        operation_symbols=symbols,
        transfers=transfers,
        machine_binding=binding,
        object_authority_rule_ids=[item.identity for item in authority.rules],
        resolved_external_environment=resolved,
        code_capabilities=callback_capabilities,
        proof_classification=proof_classification,
    )
    proof_service_bindings = [
        binding
        for entry in overlay.entries
        for binding in entry.get("service_bindings", [])
        if isinstance(binding, Mapping)
    ]
    typed_proof_service_bindings = [
        binding
        for binding in proof_service_bindings
        if binding.get("provider_kind") in {"external_call", "interface_method"}
    ]
    proof_overlay = overlay
    if typed_proof_service_bindings:
        proof_overlay = render_component_machine_overlay_v5(
            emit_proof_local_view_codec=any(has_local_views(op) for op in authored_bisimulation.operations),
            bundle=bundle,
            contract=contract,
            operation_symbols=symbols,
            transfers=transfers,
            machine_binding=binding,
            object_authority_rule_ids=[item.identity for item in authority.rules],
            resolved_external_environment=resolved,
            code_capabilities=callback_capabilities,
            proof_classification=proof_classification,
            external_service_thunk_renderer=(
                build_typed_proof_service_thunk_renderer(
                    interface=portable,
                    service_bindings=proof_service_bindings,
                    relation_evidence=relation_evidence,
                    reference_authority=authority.to_payload(), allocation_requirements=allocation_requirements,
                )
            ),
        )
        if proof_overlay.entries != overlay.entries:
            _fail("trusted proof-overlay lowering changed checked overlay metadata")
        if proof_overlay.source == overlay.source:
            _fail("trusted proof-overlay lowering did not change typed adapters")
    connected_proof_components: list[dict[str, object]] = []
    for provider_component_id in sorted(reachable_provider_ids):
        provider_input = provider_proof_inputs[provider_component_id]
        provider_operations = provider_input["operations"]
        provider_callback_capabilities: dict[str, Mapping[str, object]] = {}
        if _has_callback_projection(provider_operations):  # type: ignore[arg-type]
            assert linked is not None and linked_semantic_module is not None
            provider_callback_capabilities = (
                _checked_callback_projection_capabilities_v2(
                    operations=provider_operations,  # type: ignore[arg-type]
                    linked=linked,
                    module_interface=_load_json(
                        Path(linked_semantic_module).parent / "module-interface.json",
                        "linked module interface",
                    ),
                )
            )
        provider_overlay = render_component_machine_overlay_v5(
            bundle=provider_input["bundle"],
            contract=provider_input["contract"],  # type: ignore[arg-type]
            operation_symbols=provider_input["symbols"],  # type: ignore[arg-type]
            transfers=transfers,
            machine_binding=provider_input["binding"],  # type: ignore[arg-type]
            object_authority_rule_ids=[item.identity for item in authority.rules],
            resolved_external_environment=resolved,
            code_capabilities=provider_callback_capabilities,
            proof_classification=str(provider_input["proof_classification"]),
        )
        _, provider_portable, _, _ = _compile_kernel_semantic_contract(
            bundle=provider_input["bundle"],  # type: ignore[arg-type]
            contract=provider_input["contract"],  # type: ignore[arg-type]
            machine_binding=provider_input["binding"],  # type: ignore[arg-type]
            transfer_universe=transfer_universe,
            finite_control_routes=transfer_payload["finite_control_routes"],
            resolved_external_environment=Path(resolved_external_environment),
            provider_entry_units={
                dependency_id: provider_entries[dependency_id]
                for dependency_id in sorted(
                    provider_edges.get(provider_component_id, set())
                )
            },
            machine_image=machine_image,
        )
        provider_service_bindings = [
            service_binding
            for entry in provider_overlay.entries
            for service_binding in entry.get("service_bindings", [])
            if isinstance(service_binding, Mapping)
        ]
        provider_proof_overlay = provider_overlay
        if provider_input["trusted_adapter_lowering"] is not None:
            provider_proof_overlay = render_bound_proof_overlay(
                expected_sha256=provider_input["proof_overlay_sha256"],
                requires_local_view_codec=any("local_view_cut_policy" in op
                    for op in provider_input["proof_system"]["proof"]["models"]["operation_models"]),
                bundle=provider_input["bundle"],  # type: ignore[arg-type]
                contract=provider_input["contract"],  # type: ignore[arg-type]
                operation_symbols=provider_input["symbols"],  # type: ignore[arg-type]
                transfers=transfers,
                machine_binding=provider_input["binding"],  # type: ignore[arg-type]
                object_authority_rule_ids=[item.identity for item in authority.rules],
                resolved_external_environment=resolved,
                code_capabilities=provider_callback_capabilities,
                proof_classification=str(provider_input["proof_classification"]),
                external_service_thunk_renderer=(
                    build_typed_proof_service_thunk_renderer(
                        interface=provider_portable,
                        service_bindings=provider_service_bindings,
                        relation_evidence=provider_input["relation_evidence"],  # type: ignore[arg-type]
                        reference_authority=provider_input["proof_system"]["proof"]["models"]["reference_authority"],
                        allocation_requirements=provider_input["proof_system"]["proof"]["models"].get("reference_allocation_requirements"),
                    )
                ),
            )
            if provider_proof_overlay.entries != provider_overlay.entries:
                _fail("V6 connected-provider proof lowering changed overlay metadata")
        if (
            hashlib.sha256(provider_overlay.source.encode("ascii")).hexdigest()
            != (provider_input["proof_machine_overlay_sha256"])
        ):
            _fail("V6 connected-provider proof names a different machine overlay")
        if (
            hashlib.sha256(provider_proof_overlay.source.encode("ascii")).hexdigest()
            != provider_input["proof_overlay_sha256"]
        ):
            _fail("V6 connected-provider proof names a different proof overlay")
        if "conditional_postcondition_intent" in provider_input:
            provider_input["normal_exit_postconditions"] = checked_provider_postconditions(
                intent=provider_input["conditional_postcondition_intent"], bundle=provider_input["bundle"],
                binding=provider_input["binding_model"], proof_system=provider_input["proof_system"],
                transfers=transfers, machine_binding=provider_input["binding"], operation_symbols=provider_input["symbols"],
                resolved_external_environment=resolved, relation_evidence=provider_input["relation_evidence"],
                source_summary_artifacts=provider_input["source_summary_artifacts"], runtime_assurance=provider_input["assurance"])
        if provider_input["normal_exit_postconditions"] is not None:
            try:
                validate_provider_postconditions(provider_input["normal_exit_postconditions"],
                    bundle=provider_input["bundle"], binding=provider_input["binding_model"],
                    proof_system=provider_input["proof_system"], transfers=transfers,
                    machine_binding=provider_input["binding"], operation_symbols=provider_input["symbols"],
                    resolved_external_environment=resolved, relation_evidence=provider_input["relation_evidence"],
                    source_summary_artifacts=provider_input["source_summary_artifacts"], runtime_assurance=provider_input.get("assurance"))
            except ValueError as error:
                _fail(str(error))
        if provider_input["shared_source_contract_file_sha256"] is not None:
            try:
                requested = normal_exit_intent(provider_input["normal_exit_postconditions"]["intent"], bundle=provider_input["bundle"])
                certificate = prepare_provider_shared_contract(
                    artifacts=provider_input["source_summary_artifacts"], bundle=provider_input["bundle"],
                    source=provider_input["source"], source_profile_sha256=provider_input["source_profile"]["receipt_sha256"],
                    symbols=provider_input["symbols"], intent=requested, service_bindings=provider_service_bindings,
                    connected_components=provider_input["proof_system"]["proof"]["models"]["connected_components"],
                    expected_file_sha256=provider_input["shared_source_contract_file_sha256"])
                if certificate != provider_input["source_summary_contracts"]["certificate"]:
                    _fail("V6 shared source contract differs from its paired proof")
                check_provider_shared_binding(certificate=certificate,
                    artifacts=provider_input["source_summary_artifacts"], proof_artifacts=provider_input["proof_artifacts"],
                    normal_exit_inputs=dict(intent=requested, bundle=provider_input["bundle"], binding=provider_input["binding_model"],
                        proof_system=provider_input["proof_system"], transfers=transfers, machine_binding=provider_input["binding"],
                        operation_symbols=provider_input["symbols"], resolved_external_environment=resolved,
                        runtime_assurance=provider_input.get("assurance")))
            except (ValueError, TypeError, KeyError) as error:
                _fail(str(error))
        connected_proof_components.append(
            {
                "component_id": provider_component_id,
                **({"assurance": provider_input["assurance"], "authorizing": False} if "assurance" in provider_input else {}),
                "compiled_interface": provider_input["bundle"],
                "operation_symbols": provider_input["symbols"],
                "source_package": provider_input["source_root"],
                "source_profile": provider_input["source_profile"],
                "machine_overlay_source": provider_overlay.source,
                "trusted_proof_overlay_source": (
                    None
                    if provider_proof_overlay is provider_overlay
                    else provider_proof_overlay.source
                ),
                "trusted_adapter_lowering": provider_input["trusted_adapter_lowering"],
                "machine_overlay_entries": list(provider_overlay.entries),
                "c_headers": render_component_c_headers_v5(
                    provider_input["bundle"],  # type: ignore[arg-type]
                    provider_input["symbols"],  # type: ignore[arg-type]
                ),
                "binding_intent_sha256": provider_input["binding_model"].intent_sha256,
                "qualification_sha256": provider_input["qualification_sha256"],
                "contextual_refinement_sha256": provider_input[
                    "contextual_refinement_sha256"
                ],
                "proof_receipt_sha256": provider_input["proof_receipt_sha256"],
                "source_summary_contracts": provider_input["source_summary_contracts"],
                "source_summary_artifacts": provider_input["source_summary_artifacts"],
                **{key: provider_input[key] for key in ("proof_system", "binding_intent", "proof_artifacts")},
            }
        )
    if exact_c_slice is None:
        _fail("direct Portable-C qualification requires an exact-C slice")
    operation_sources = operation_sources_from_package(
        source_root=source_root,
        source=source,
        symbols=symbols,
    )
    proof_plan = build_component_proof_plan_v1(
        component_id=component_id,
        semantic_contract_sha256=str(semantic_contract["contract_sha256"]),
        interface=portable,
        operations=[
            row for row in semantic_contract["operations"] if isinstance(row, Mapping)
        ],
        operation_sources=operation_sources,
        source_package_sha256=str(source["implementation_sha256"]),
        intent=authored_bisimulation,
    )
    write_json(output / "component-proof-plan-v1.json", proof_plan)
    exact_context = build_exact_context(
        proof_plan=proof_plan, linked=linked, owned=semantic_slice_model,
    )
    exact_c_slice_path = Path(exact_c_slice)
    exact_c_slice_manifest = dict(
        _load_json(exact_c_slice_path, "component exact-C slice V1")
    )
    _validate_exact_c_slice(
        manifest=exact_c_slice_manifest,
        root=exact_c_slice_path.parent,
        component_id=component_id,
        operations=operations,
        bisimulation_intent_sha256=(authored_bisimulation.intent_sha256),
        executable_transfer_plan_sha256=sha256_file(transfer_path),
        dependency_components=exact_dependency_components,
    )
    with tempfile.TemporaryDirectory(prefix="spx-exact-c-recheck-") as temporary:
        regenerated = write_component_exact_c_slice_v1(
            component_id=component_id,
            transfers=transfers,
            operations=[
                {
                    "operation_id": str(row["operation_id"]),
                    "unit_ids": list(row["unit_ids"]),
                    "context_unit_ids": list(row["context_transfer_ids"]),
                    "continuation_unit_ids": list(row["machine_projection"].get("operation", {}).get("continuation_unit_ids", [])),
                    "entry_rvas": list(row["entry_rvas"]),
                }
                for row in operations
            ],
            intent=authored_bisimulation,
            executable_transfer_plan_sha256=sha256_file(transfer_path),
            out=Path(temporary),
            dependency_components=[
                {
                    "component_id": dependency_id,
                    "binding_intent_sha256": row["binding_intent_sha256"],
                    "operations": row["operations"],
                }
                for dependency_id, row in sorted(exact_dependency_components.items())
            ],
        )
        if regenerated != exact_c_slice_manifest:
            _fail("component exact-C slice differs from deterministic rerender")
    shutil.copytree(exact_c_slice_path.parent, output / "exact-c")
    semantic_operations = {
        str(row["operation_id"]): row
        for row in semantic_contract["operations"]
        if isinstance(row, Mapping)
    }
    if set(semantic_operations) != {
        operation.semantics.operation_id for operation in binding_model.operations
    }:
        _fail("contextual proof operation inventory is inconsistent")
    retained_shared_contract = None
    if shared_source_contract_artifacts is not None:
        try:
            retained_shared_contract = prepare_provider_shared_contract(
                artifacts=shared_source_contract_artifacts, bundle=bundle, source=source,
                source_profile_sha256=source_profile["receipt_sha256"], symbols=symbols,
                intent=requested_postconditions, service_bindings=proof_service_bindings,
                connected_components=connected_proof_components, output=output / "source-summary-contracts",
                expected_file_sha256=qualification_input["shared_source_contract_file_sha256"])
        except (ValueError, TypeError, KeyError) as error:
            _fail(str(error))
    # Production compilation is a cheap veto, never proof authority. Check it
    # before solver work; focused/conditional runs still emit no native objects.
    if runtime_assurance is None and selected_obligations is None:
        component_output = output / "component-object"
        component_output.mkdir()
        runtime_header = exact_runtime_header()
        compile_checks, compile_status, _artifact = compile_portable_component_objects(
            source_root,
            source,
            bundle=bundle,
            operation_symbols=symbols,
            induction_source_plan=None,
            machine_overlay=overlay,
            machine_overlay_error=None,
            runtime_header=runtime_header,
            host_compiler=Path(host_compiler),
            pe32_compiler=Path(pe32_compiler),
            output=component_output,
        )
        manifest_path = component_output / "object-manifest.json"
        if not manifest_path.is_file():
            failures = [
                {
                    key: row.get(key)
                    for key in ("compiler", "source", "code", "status", "diagnostic")
                    if row.get(key) is not None
                }
                for row in compile_checks
                if row.get("status") != "checked"
            ]
            _fail(
                "direct portable component did not emit an object manifest: "
                + repr(failures)
            )
    shard_proof = check_bisimulation_refinement(
        selected_obligations=selected_obligations,
        runtime_assurance=runtime_assurance,
        smt_solver=smt_solver,
        reference_authority=authority.to_payload(),
        reference_allocation_requirements=allocation_requirements,
        semantic_contract=semantic_contract,
        interface=portable,
        source_package=source_root,
        source_profile=source_profile,
        intent=authored_bisimulation,
        exact_c_root=exact_c_slice_path.parent,
        exact_c_slice=exact_c_slice_manifest,
        machine_overlay_source=overlay.source,
        trusted_proof_overlay_source=(
            None if proof_overlay is overlay else proof_overlay.source
        ),
        machine_overlay_entries=overlay.entries,
        machine_projections={
            operation.semantics.operation_id: {
                **operation.semantics.machine_projection,
                "operation": semantic_operations[operation.semantics.operation_id],
            }
            for operation in binding_model.operations
        },
        cbmc=Path(cbmc),
        c_headers=render_component_c_headers_v5(bundle, symbols),
        connected_components=connected_proof_components,
        relation_evidence=relation_evidence,
        timeout_seconds=timeout_seconds,
        source_entry_timeout_seconds=source_entry_timeout_seconds,
        diagnostic_root=output / "proof-diagnostics", proof_workspace=proof_workspace,
        previous_query_evidence=previous_query_evidence,
    )
    if runtime_assurance is not None:
        # Conditional evidence is a separate exit. The full refinement checker
        # runs, but no provider qualification, native objects or choices follow.
        from ..components.formats import CONDITIONAL_CONTEXTUAL_CHECK_V1_FORMAT
        from ..components.contextual_bisimulation import build_conditional_contextual_refinement_v1
        if pending_requirements or selected_obligations is not None:
            # Retain query evidence for investigation/reuse, but export no local
            # supplier theorem while boundary requirements remain unresolved.
            from ..components.conditional_check_result import conditional_packet_status
            if (output / "conditional-refinement-result.json").exists():
                _fail("pending boundary requirements conflict with an existing supplier theorem")
            if pending_requirements:
                shard_proof["boundary_requirements"] = pending_requirements
            shard_proof["receipt_sha256"] = canonical_sha256_v3(
                {k: v for k, v in shard_proof.items() if k != "receipt_sha256"})
            packet_path = output / "conditional-engine-result.json"
            write_json(packet_path, {"format": CONDITIONAL_CONTEXTUAL_CHECK_V1_FORMAT,
                "status": conditional_packet_status(shard_proof), "inputs": qualification_input,
                "inputs_sha256": qualification_input_sha256, "result": shard_proof, "authorizing": False})
            return {"conditional_check": packet_path}
        conditional_models = dict(shard_proof["bindings"])
        if retained_shared_contract is not None:
            conditional_models["source_summary_contracts"] = {
                "implementation_sha256": source["implementation_sha256"],
                "source_profile_sha256": source_profile["receipt_sha256"],
                "proof_interface_sha256": conditional_models["interface_sha256"],
                "certificate": retained_shared_contract,
            }
        conditional_proof = build_conditional_contextual_refinement_v1(
            runtime_assurance=runtime_assurance, proof_plan=proof_plan,
            exact_c_slice=exact_c_slice_manifest,
            implementation_sha256=str(source["implementation_sha256"]),
            source_profile_sha256=str(source_profile["receipt_sha256"]),
            checker=shard_proof["checker"], models=conditional_models,
            shard_results=shard_proof["checks"],
            world=_component_proof_world_v1(bundle=bundle,
                binding_intent_sha256=binding_model.intent_sha256,
                machine_object_authority_sha256=authority.authority_sha256,
                checked_component_summaries_used=any(
                    row["summary_strategy"] in {"scalar-body-free-v1", "image-readable-body-free-v1", "image-mutable-body-free-v1", "image-shared-body-free-v1", "image-shared-framed-body-free-v1"}
                    for row in shard_proof["bindings"]["connected_components"])),
        )
        if conditional_proof["status"] == "satisfied" and requested_postconditions is not None:
            normal_exit_inputs = dict(intent=requested_postconditions, bundle=bundle, binding=binding_model,
                proof_system={"proof": conditional_proof, "proof_plan": proof_plan, "exact_c_slice": exact_c_slice_manifest},
                transfers=transfers, machine_binding=binding, operation_symbols=symbols,
                resolved_external_environment=resolved, relation_evidence=relation_evidence,
                runtime_assurance=runtime_assurance)
            checked_provider_postconditions(**normal_exit_inputs,
                source_summary_artifacts=output / "source-summary-contracts" if retained_shared_contract is not None else None)
            if retained_shared_contract is not None:
                check_provider_shared_binding(certificate=retained_shared_contract,
                    artifacts=output / "source-summary-contracts", proof_artifacts=output / "proof-diagnostics",
                    normal_exit_inputs=normal_exit_inputs)
        refinement_path = output / "conditional-refinement-result.json"
        write_json(refinement_path, conditional_proof)
        packet_path = output / "conditional-engine-result.json"
        write_json(packet_path, {"format": CONDITIONAL_CONTEXTUAL_CHECK_V1_FORMAT,
            "status": shard_proof["status"], "inputs": qualification_input,
            "inputs_sha256": qualification_input_sha256, "result": shard_proof, "authorizing": False})
        return {"conditional_check": packet_path, "conditional_refinement": refinement_path}
    proof_models = dict(shard_proof["bindings"])
    summary_contracts = retained_shared_contract if retained_shared_contract is not None else check_provider_source_contracts(
        bundle=bundle, symbols=symbols, source=source, source_root=source_root,
        output=output / "source-summary-contracts", cbmc=cbmc,
        timeout_seconds=timeout_seconds, workspace=source_summary_workspace,
        connected_components=connected_proof_components, proof_models=proof_models,
        postcondition_intent=requested_postconditions,
    )
    if summary_contracts is not None:
        proof_models["source_summary_contracts"] = {
            "implementation_sha256": source["implementation_sha256"],
            "source_profile_sha256": source_profile["receipt_sha256"],
            "proof_interface_sha256": proof_models["interface_sha256"],
            "certificate": summary_contracts,
        }
    proof = build_contextual_refinement_v2(
        proof_plan=proof_plan,
        exact_c_slice=exact_c_slice_manifest,
        implementation_sha256=str(source["implementation_sha256"]),
        source_profile_sha256=str(source_profile["receipt_sha256"]),
        checker=dict(shard_proof["checker"]),
        models=proof_models,
        shard_results=[
            row for row in shard_proof["checks"] if isinstance(row, Mapping)
        ],
        world=_component_proof_world_v1(
            bundle=bundle,
            binding_intent_sha256=binding_model.intent_sha256,
            machine_object_authority_sha256=authority.authority_sha256,
            checked_component_summaries_used=any(
                row["summary_strategy"] in {"scalar-body-free-v1", "image-readable-body-free-v1", "image-mutable-body-free-v1", "image-shared-body-free-v1", "image-shared-framed-body-free-v1"}
                for row in proof_models["connected_components"]
            ),
        ),
    )
    validate_contextual_refinement_v2(
        proof,
        proof_plan=proof_plan,
        exact_c_slice=exact_c_slice_manifest,
        implementation_sha256=str(source["implementation_sha256"]),
    )
    proof_status = str(proof.get("status"))
    if selected_obligations is not None:
        # Ordinary diagnostics use the same checked proof envelope and exact
        # query evidence. No native object, supplier theorem or choice is emitted.
        packet_path = output / 'contextual-refinement-result.json'
        write_json(packet_path, {'status': proof_status, 'proof': proof,
            'qualification_input': qualification_input,
            'qualification_input_sha256': qualification_input_sha256,
            'proof_plan': proof_plan, 'exact_c_slice': exact_c_slice_manifest})
        diagnostic_path = output / 'contextual-proof-diagnostic.json'
        write_json(diagnostic_path, proof)
        return {'proof_diagnostic': diagnostic_path, 'contextual_refinement': packet_path}
    postconditions = None
    if requested_postconditions is not None:
        postconditions = {"authorizing": False, "intent": requested_postconditions.to_payload(), "facts": []}
        if proof_status == "satisfied" and proof.get("activation_authorized") is True:
            try:
                postconditions = checked_provider_postconditions(intent=requested_postconditions,
                    bundle=bundle, binding=binding_model,
                    proof_system={"proof": proof, "proof_plan": proof_plan, "exact_c_slice": exact_c_slice_manifest},
                    transfers=transfers, machine_binding=binding, operation_symbols=symbols,
                    resolved_external_environment=resolved, relation_evidence=relation_evidence,
                    source_summary_artifacts=output / "source-summary-contracts" if retained_shared_contract is not None else None)
            except ValueError as error:
                _fail(str(error))
    if retained_shared_contract is not None and proof_status == "satisfied" and proof.get("activation_authorized") is True:
        try:
            check_provider_shared_binding(certificate=retained_shared_contract, artifacts=output / "source-summary-contracts",
                proof_artifacts=output / "proof-diagnostics",
                normal_exit_inputs=dict(intent=requested_postconditions, bundle=bundle, binding=binding_model,
                    proof_system={"proof": proof, "proof_plan": proof_plan, "exact_c_slice": exact_c_slice_manifest},
                    transfers=transfers, machine_binding=binding, operation_symbols=symbols, resolved_external_environment=resolved))
        except (ValueError, TypeError, KeyError) as error:
            _fail(str(error))
    refinement_status = {
        "satisfied": "checked",
        "incomplete": "incomplete",
        "violated": "incomplete",
    }.get(proof_status)
    if refinement_status is None:
        _fail("contextual-refinement checker returned an unknown status")
    if (proof.get("activation_authorized") is not True and
            (exact_context is None or any("entry_allocation_history" in operation["source"]
                                         for operation in proof_plan["operations"]))):
        # Conditional local proofs qualify only with a machine-derived context
        # requirement, enforced again by selection and exact native linking.
        # A continuation context does not discharge incoming heap premises.
        refinement_status = "incomplete"
    refinement_receipt = canonical_sha256_v3(
        {
            "qualification_input_sha256": qualification_input_sha256,
            "source_package_sha256": source["implementation_sha256"],
            "semantic_contract_sha256": proof_plan["bindings"][
                "semantic_contract_sha256"
            ],
            "cbmc_sha256": sha256_file(Path(cbmc)),
            "proof": proof,
            "relation_evidence": relation_evidence,
            **({"normal_exit_postconditions": postconditions} if postconditions is not None else {}),
            "proof_plan_sha256": proof_plan["plan_sha256"],
            "exact_c_slice_sha256": exact_c_slice_manifest["slice_sha256"],
        }
    )

    if authority.bindings.get("original_pe_sha256") != transfer_bindings["pe_sha256"]:
        _fail("machine object authority binds another module")
    encapsulated_admission = None
    if proof_classification == "encapsulated_owned":
        assert linked is not None
        encapsulated_admission = check_encapsulated_owned_admission(
            component_id=component_id,
            proof_classification=proof_classification,
            operations=operations,
            semantic_slice=semantic_slice_model,
            qualification_input_sha256=qualification_input_sha256,
            bundle=bundle,
            linked=linked,
            transfers=transfers,
            authority=authority,
        )
        write_json(
            output / "encapsulated-owned-admission.json",
            encapsulated_admission,
        )
    component_manifest = dict(
        _load_json(
            manifest_path,
            "direct portable component object manifest",
        )
    )
    original_artifact = component_manifest.pop("artifact_sha256", None)
    if original_artifact != canonical_sha256_v3(component_manifest):
        _fail("direct portable component object manifest is stale")
    component_manifest.update(
        {
            "qualification_input_sha256": qualification_input_sha256,
            "component_id": component_id,
            "proof_classification": proof_classification,
            "semantic_slice_sha256": semantic_slice_model.identity,
            "contextual_refinement_sha256": refinement_receipt,
            "proof_plan_sha256": proof_plan["plan_sha256"],
            "exact_c_slice_sha256": (exact_c_slice_manifest["slice_sha256"]),
            "encapsulated_owned_admission_sha256": (
                None
                if encapsulated_admission is None
                else encapsulated_admission["receipt_sha256"]
            ),
        }
    )
    component_manifest["artifact_sha256"] = canonical_sha256_v3(component_manifest)
    write_json(manifest_path, component_manifest)

    pe32_rows = [
        dict(row)
        for row in component_manifest["objects"]
        if row.get("compiler") == "pe32"
    ]
    if not pe32_rows:
        _fail("direct portable component has no PE32 objects")
    objects_root = output / "objects"
    objects_root.mkdir()
    source_provenance = {
        str(row["path"]): str(row["sha256"])
        for row in source.get("files", [])
        if isinstance(row, Mapping)
    }
    source_provenance.update(
        {
            Path(str(row["path"])).name: str(row["sha256"])
            for row in component_manifest["generated"]
        }
    )
    object_hashes: list[str] = []
    provider_objects = []
    for index, row in enumerate(sorted(pe32_rows, key=lambda item: item["path"])):
        source_object = component_output / str(row["path"])
        digest = sha256_file(source_object)
        if digest != row["sha256"]:
            _fail("direct portable component object binding is stale")
        destination = objects_root / f"{index:04d}-{digest[:16]}.o"
        shutil.copyfile(source_object, destination)
        source_name = str(row["source"])
        source_sha256 = source_provenance.get(source_name)
        if source_sha256 is None:
            _fail("direct portable object lacks exact source provenance")
        object_hashes.append(digest)
        provider_objects.append(
            {
                "source": f"component:{component_id}/" + source_name,
                "source_owner": "portable_c",
                "source_sha256": source_sha256,
                "object_sha256": digest,
                "path": destination.relative_to(output).as_posix(),
                "language": "precompiled-object",
            }
        )
    object_hashes = sorted(set(object_hashes))
    source_hashes = sorted(
        {
            str(source["implementation_sha256"]),
            *(str(row["sha256"]) for row in component_manifest["generated"]),
        }
    )
    provider_manifest_core = {
        "materialization": "portable-work-package-provider-v2",
        "qualification_input_sha256": qualification_input_sha256,
        "component_id": component_id,
        "proof_classification": proof_classification,
        "semantic_slice_sha256": semantic_slice_model.identity,
        "implementation_sha256": str(source["implementation_sha256"]),
        "contextual_refinement_sha256": refinement_receipt,
        "proof_plan_sha256": proof_plan["plan_sha256"],
        "exact_c_slice_sha256": (exact_c_slice_manifest["slice_sha256"]),
        "encapsulated_owned_admission_sha256": (
            None
            if encapsulated_admission is None
            else encapsulated_admission["receipt_sha256"]
        ),
        "compiler_sha256": sha256_file(Path(pe32_compiler)),
        "nm_sha256": sha256_file(Path(nm)),
        "machine_overlay_source_sha256": hashlib.sha256(
            overlay.source.encode("ascii")
        ).hexdigest(),
        "machine_overlay_object_sha256": next(
            (
                row["object_sha256"]
                for row in provider_objects
                if row["source_sha256"]
                == hashlib.sha256(overlay.source.encode("ascii")).hexdigest()
            ),
            None,
        ),
        "machine_overlays": component_manifest["machine_overlays"],
        "objects": provider_objects,
    }
    if (
        provider_manifest_core["machine_overlay_object_sha256"] is None
        or sum(
            row["source_sha256"]
            == provider_manifest_core["machine_overlay_source_sha256"]
            for row in provider_objects
        )
        != 1
    ):
        _fail("direct portable provider has no unique machine-overlay object")
    provider_manifest = output / "provider-object-manifest.json"
    write_json(
        provider_manifest,
        {
            **provider_manifest_core,
            "receipt_sha256": canonical_sha256_v3(provider_manifest_core),
        },
    )

    overlay_by_unit: dict[str, Mapping[str, object]] = {}
    for row in overlay.entries:
        for unit_id in row["owned_unit_ids"]:
            if unit_id in overlay_by_unit:
                _fail("direct portable overlay ownership is ambiguous")
            overlay_by_unit[str(unit_id)] = row
    definitions = []
    choices: dict[str, str] = {}
    for definition in semantic_slice_model.payload["definitions"]:
        symbol_id = str(definition["symbol_id"])
        prefix = "original:function:"
        if not symbol_id.startswith(prefix):
            _fail("direct portable slice contains a non-transfer definition")
        unit_id = symbol_id[len(prefix) :]
        overlay_row = overlay_by_unit.get(unit_id)
        if overlay_row is None:
            _fail("direct portable overlay omits a slice definition")
        definition_id = str(definition["definition_id"])
        definitions.append(
            {
                "definition_id": definition_id,
                "native_symbol": str(overlay_row["symbol"]),
                "source_sha256s": source_hashes,
                "object_sha256s": object_hashes,
            }
        )
        choices[definition_id] = provider_id

    tool_sha256s = sorted(
        {
            sha256_file(Path(host_compiler)),
            sha256_file(Path(pe32_compiler)),
            sha256_file(Path(nm)),
            sha256_file(Path(cbmc)),
        }
    )
    common_inputs = {
        "qualification_input": qualification_input_sha256,
        "source_package": str(source["implementation_sha256"]),
        "object_manifest": sha256_file(provider_manifest),
        "proof_classification": proof_classification,
        "provenance_artifact_sha256s": provenance_sha256s,
    }
    facet_status = {
        "compile": compile_status,
        "contextual_refinement": refinement_status,
        "bisimulation": refinement_status,
        "lifecycle": "checked",
        "native_objects": "checked" if object_hashes else "incomplete",
        "object_binding": "checked",
        "ownership": "checked",
        "relations": "checked"
        if (relation_intent is None or relation_evidence or postconditions is not None and postconditions["facts"])
        else "incomplete",
        "services": "checked",
        "source": "checked",
    }
    facets = [
        {
            "name": name,
            "status": facet_status[name],
            "receipt_sha256": canonical_sha256_v3(
                {
                    **common_inputs,
                    "facet": name,
                    "status": facet_status[name],
                    **(
                        {"proof_receipt_sha256": refinement_receipt}
                        if name == "contextual_refinement"
                        else {}
                    ),
                    **(
                        {"encapsulated_owned_admission": encapsulated_admission}
                        if name in {"lifecycle", "ownership"}
                        and encapsulated_admission is not None
                        else {}
                    ),
                    **({"evidence": relation_evidence} if name == "relations" else {}),
                    **({"normal_exit_postconditions": postconditions}
                       if name == "relations" and postconditions is not None else {}),
                    **({"checks": compile_checks} if name == "compile" else {}),
                }
            ),
        }
        for name in sorted(facet_status)
    ]

    qualification = output / "semantic-provider-qualification.json"
    write_semantic_provider_qualification_v2(
        exact_context=exact_context,
        semantic_slice=semantic_slice_model,
        provider_id=provider_id,
        provider_kind="qualified_portable_c",
        provider_artifact_sha256=canonical_sha256_v3(
            {
                **common_inputs,
                "contextual_refinement": refinement_receipt,
                "component_object_artifact": component_manifest["artifact_sha256"],
            }
        ),
        facets=facets,
        definition_materializations=definitions,
        tool_sha256s=tool_sha256s,
        dependencies=sorted(
            {
                *(
                    f"semantic-contract:{item}"
                    for item in semantic_slice_model.payload[
                        "dependency_contract_sha256s"
                    ]
                ),
                *(
                    f"interaction-contract:{row['contract_sha256']}"
                    for row in relation_evidence
                ),
                *(
                    f"interaction-receipt:{row['contract_receipt_sha256']}"
                    for row in relation_evidence
                ),
                *(
                    f"provider-provenance:{artifact_id}:{artifact_sha256}"
                    for artifact_id, artifact_sha256 in provenance_sha256s.items()
                ),
                *([f"normal-exit-relation:{requested_postconditions.intent_sha256}"]
                  if requested_postconditions is not None else []),
                f"contextual-refinement:{refinement_receipt}",
                f"component-proof-plan:{proof_plan['plan_sha256']}",
                "component-exact-c-slice:"
                + str(exact_c_slice_manifest["slice_sha256"]),
            }
        ),
        out=qualification,
    )
    choices_path = output / "definition-choices.json"
    write_json(choices_path, choices)
    implementation_choices = {
        "definitions": {},
        "obligations": {},
    }
    if generated_choices is not None:
        inherited = _load_json(
            Path(generated_choices),
            "generated definition choices",
        )
        if any(
            not isinstance(key, str) or not isinstance(value, str)
            for key, value in inherited.items()
        ):
            _fail("generated definition choices are malformed")
        implementation_choices["definitions"].update(inherited)
    implementation_choices["definitions"].update(choices)
    implementation_choices_path = output / "implementation-choices.json"
    write_json(implementation_choices_path, implementation_choices)
    write_json(
        output / "contextual-refinement-result.json",
        {
            "status": proof_status,
            "receipt_sha256": refinement_receipt,
            "qualification_input": qualification_input,
            "qualification_input_sha256": qualification_input_sha256,
            "source_package_sha256": source["implementation_sha256"],
            "proof": proof,
            "relation_evidence": relation_evidence,
            **({"normal_exit_postconditions": postconditions} if postconditions is not None else {}),
            "proof_plan": proof_plan,
            "exact_c_slice": exact_c_slice_manifest,
            "proof_classification": proof_classification,
            "encapsulated_owned_admission": encapsulated_admission,
            "policy": {"tests_authorize": False, "cbmc_required": True},
        },
    )
    return {
        "qualification": qualification,
        "definition_choices": choices_path,
        "implementation_choices": implementation_choices_path,
        "object_manifest": provider_manifest,
        "contextual_refinement": output / "contextual-refinement-result.json",
    }


__all__ = [
    "PortableCWorkPackageError",
    "write_portable_c_work_package_provider_v2",
]
